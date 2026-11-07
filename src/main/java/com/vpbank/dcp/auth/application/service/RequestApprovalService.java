package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.command.RegisterPendingDeviceCommand;
import com.vpbank.dcp.auth.application.command.RequestApprovalCommand;
import com.vpbank.dcp.auth.application.port.in.RequestApprovalUseCase;
import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.result.KnownDeviceSummary;
import com.vpbank.dcp.auth.application.result.RequestApprovalResult;
import com.vpbank.dcp.auth.domain.model.AdmittedSession;
import com.vpbank.dcp.auth.domain.model.ApprovalRequestStart;
import com.vpbank.dcp.auth.domain.model.DeviceEnrollment;
import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import com.vpbank.dcp.auth.domain.model.EnrollmentPolicy;
import com.vpbank.dcp.auth.domain.model.TrustedDevice;
import java.time.Clock;
import java.util.Optional;
import java.util.function.Supplier;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/**
 * The new device, on its restricted session, asks the customer's primary device to trust it (DD 20 §4,
 * slice 6): it registers a PENDING device row and an approval request that waits as long as that row does.
 * A request belongs to the device, not to the restricted session that made it: one open request per device,
 * which a later login of the same device gets back.
 *
 * <p>Six collaborators: the request reads both enrollment stores (the cache, to refuse a session already in the
 * primary enrollment, and SQL), registers the device row, and needs an ID, the policy window and the clock.
 */
@RequiredArgsConstructor
public final class RequestApprovalService implements RequestApprovalUseCase {
    @NonNull
    private final ApprovalRequests approvalRequests;
    @NonNull
    private final EnrollmentTransactions enrollmentTransactions;
    @NonNull
    private final TrustedDeviceService trustedDeviceService;
    @NonNull
    private final Supplier<EnrollmentId> enrollmentIdGenerator;
    @NonNull
    private final EnrollmentPolicy enrollmentPolicy;
    @NonNull
    private final Clock clock;

    @Override
    public RequestApprovalResult request(RequestApprovalCommand command) {
        AdmittedSession newDeviceSession = command.admitted();
        if (!newDeviceSession.restricted()) {
            return new RequestApprovalResult.Conflict();
        }
        try {
            // The primary enrollment (FACE on this device) already started on this session.
            if (enrollmentTransactions.wasStartedBy(newDeviceSession)) {
                return new RequestApprovalResult.Conflict();
            }
            // One open request per device: asking again, from this login or a later one, gets the same request.
            Optional<DeviceEnrollment> openRequest = openRequestOf(newDeviceSession);
            if (openRequest.isPresent()) {
                return waitingApproval(openRequest.get());
            }
            return startNewRequest(command);
        } catch (RepositoryUnavailableException failure) {
            return new RequestApprovalResult.Unavailable();
        }
    }

    /** Registers the PENDING device row the request targets, then stores the request itself. */
    private RequestApprovalResult startNewRequest(RequestApprovalCommand command) {
        if (isUnknownDeviceWithoutKey(command)) {
            return new RequestApprovalResult.DeviceKeyRequired();
        }
        Optional<TrustedDevice> targetDevice = registerPendingDevice(command);
        if (targetDevice.isEmpty()) {
            return new RequestApprovalResult.TooManyPending();
        }
        return storeRequest(command.admitted(), targetDevice.get());
    }

    private Optional<DeviceEnrollment> openRequestOf(AdmittedSession newDeviceSession) {
        Optional<DeviceEnrollment> latestRequest = approvalRequests.latestOf(newDeviceSession);
        if (latestRequest.isEmpty()) {
            return Optional.empty();
        }
        boolean stillOpen = latestRequest.get().isOpen(clock.instant());
        if (!stillOpen) {
            return Optional.empty();
        }
        return latestRequest;
    }

    /** An unknown installation must send its key and platform; a known live row keeps what Auth already stores. */
    private boolean isUnknownDeviceWithoutKey(RequestApprovalCommand command) {
        AdmittedSession newDeviceSession = command.admitted();
        Optional<KnownDeviceSummary> knownDevice = trustedDeviceService.knownDevice(
                newDeviceSession.customerId(),
                newDeviceSession.channel(),
                newDeviceSession.deviceId());
        boolean sentNoKey = command.devicePublicJwk() == null || command.platform() == null;
        return knownDevice.isEmpty() && sentNoKey;
    }

    /** The PENDING row the request targets (the live row of a known device); empty when too many devices wait. */
    private Optional<TrustedDevice> registerPendingDevice(RequestApprovalCommand command) {
        AdmittedSession newDeviceSession = command.admitted();
        RegisterPendingDeviceCommand registration = RegisterPendingDeviceCommand.builder()
                .newDeviceSession(newDeviceSession)
                .devicePublicJwk(command.devicePublicJwk())
                .platform(command.platform())
                .enrollmentPolicy(enrollmentPolicy)
                .correlationId(newDeviceSession.sessionId().toString())
                .build();
        return trustedDeviceService.registerPendingDevice(registration);
    }

    /** The request waits as long as its PENDING device row does; Auth does not read the session's deadline. */
    private RequestApprovalResult storeRequest(AdmittedSession newDeviceSession, TrustedDevice targetDevice) {
        ApprovalRequestStart start = ApprovalRequestStart.builder()
                .enrollmentId(enrollmentIdGenerator.get())
                .requester(newDeviceSession.installation())
                .targetDeviceId(targetDevice.id())
                .expiresAt(clock.instant().plus(enrollmentPolicy.pendingWindow()))
                .build();
        DeviceEnrollment freshRequest = DeviceEnrollment.requestApproval(start);
        DeviceEnrollment storedRequest = approvalRequests.create(freshRequest, newDeviceSession.sessionId());

        // This session already made a request that is closed now (UQ_DE_CREATION): it cannot make another.
        if (!storedRequest.id().equals(freshRequest.id())) {
            return answerForEarlier(storedRequest);
        }
        return waitingApproval(storedRequest);
    }

    private RequestApprovalResult answerForEarlier(DeviceEnrollment earlierRequest) {
        boolean stillWaiting = earlierRequest.isApproval() && earlierRequest.isOpen(clock.instant());
        if (stillWaiting) {
            return waitingApproval(earlierRequest);
        }
        return new RequestApprovalResult.Conflict();
    }

    private static RequestApprovalResult waitingApproval(DeviceEnrollment request) {
        return new RequestApprovalResult.WaitingApproval(request.id(), request.expiresAt());
    }
}
