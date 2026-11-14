package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.command.RequestApprovalCommand;
import com.vpbank.dcp.auth.application.port.in.RequestApprovalUseCase;
import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.port.out.repository.EnrollmentRepository.ApprovalReservation;
import com.vpbank.dcp.auth.application.result.KnownDeviceSummary;
import com.vpbank.dcp.auth.application.result.RequestApprovalResult;
import com.vpbank.dcp.auth.domain.model.AdmittedSession;
import com.vpbank.dcp.auth.domain.model.ApprovalRequestStart;
import com.vpbank.dcp.auth.domain.model.DeviceEnrollment;
import com.vpbank.dcp.auth.domain.model.DeviceKey;
import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import com.vpbank.dcp.auth.domain.model.EnrollmentPolicy;
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
                return answerForEarlier(openRequest.get(), command);
            }
            return startNewRequest(command);
        } catch (RepositoryUnavailableException failure) {
            return new RequestApprovalResult.Unavailable();
        }
    }

    private RequestApprovalResult startNewRequest(RequestApprovalCommand command) {
        AdmittedSession newDeviceSession = command.admitted();
        Optional<KnownDeviceSummary> existingBinding = trustedDeviceService.knownDevice(
                newDeviceSession.customerId(),
                newDeviceSession.channel(),
                newDeviceSession.deviceId());
        Optional<DeviceKey> candidateKey = candidateKeyOf(command, existingBinding);
        if (candidateKey.isEmpty()) {
            return new RequestApprovalResult.DeviceKeyRequired();
        }
        if (!matchesCandidate(command, candidateKey.get())) {
            return new RequestApprovalResult.Conflict();
        }
        ApprovalRequestStart start = ApprovalRequestStart.builder()
                .enrollmentId(enrollmentIdGenerator.get())
                .requester(newDeviceSession.installation())
                .candidateKey(candidateKey.get())
                .targetDeviceId(existingBinding.map(KnownDeviceSummary::id).orElse(null))
                .expiresAt(clock.instant().plus(enrollmentPolicy.pendingWindow()))
                .build();
        DeviceEnrollment freshRequest = DeviceEnrollment.requestApproval(start);
        ApprovalReservation reservation = approvalRequests.reserve(
                freshRequest, newDeviceSession.sessionId(), enrollmentPolicy.maxPendingDevices());
        return switch (reservation) {
            case ApprovalReservation.QuotaReached() -> new RequestApprovalResult.TooManyPending();
            case ApprovalReservation.Reserved(DeviceEnrollment storedRequest) -> answerForEarlier(storedRequest, command);
        };
    }

    private static Optional<DeviceKey> candidateKeyOf(RequestApprovalCommand command,
                                                       Optional<KnownDeviceSummary> existingBinding) {
        if (existingBinding.isPresent()) {
            KnownDeviceSummary binding = existingBinding.get();
            if (binding.publicKey() != null) {
                return Optional.of(new DeviceKey(binding.publicKey(), binding.platform()));
            }
        }
        if (command.devicePublicJwk() == null || command.platform() == null) {
            return Optional.empty();
        }
        return Optional.of(new DeviceKey(command.devicePublicJwk(), command.platform()));
    }

    private Optional<DeviceEnrollment> openRequestOf(AdmittedSession newDeviceSession) {
        return approvalRequests.latestOf(newDeviceSession).filter(request -> request.isOpen(clock.instant()));
    }

    private RequestApprovalResult answerForEarlier(DeviceEnrollment earlierRequest, RequestApprovalCommand command) {
        DeviceKey candidateKey = earlierRequest.candidateKey();
        if (earlierRequest.isApproval() && earlierRequest.isOpen(clock.instant()) && matchesCandidate(command, candidateKey)) {
            return waitingApproval(earlierRequest);
        }
        return new RequestApprovalResult.Conflict();
    }

    private static boolean matchesCandidate(RequestApprovalCommand command, DeviceKey candidateKey) {
        return candidateKey != null
                && (command.devicePublicJwk() == null || command.devicePublicJwk().equals(candidateKey.publicJwk()))
                && (command.platform() == null || command.platform() == candidateKey.platform());
    }

    private static RequestApprovalResult waitingApproval(DeviceEnrollment request) {
        return new RequestApprovalResult.WaitingApproval(request.id(), request.expiresAt());
    }
}
