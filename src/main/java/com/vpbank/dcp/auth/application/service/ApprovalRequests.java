package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.port.out.repository.EnrollmentRepository;
import com.vpbank.dcp.auth.domain.enums.EnrollmentState;
import com.vpbank.dcp.auth.domain.model.AdmittedSession;
import com.vpbank.dcp.auth.domain.model.DeviceEnrollment;
import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import com.vpbank.dcp.auth.domain.model.SessionId;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/**
 * The approval flow's view of {@link EnrollmentRepository} (slice 6, slice 11). The new device finds its own
 * latest request; the primary device finds the requests of its customer that are still open. Every write is a
 * compare-and-set on the version read.
 */
@RequiredArgsConstructor
public final class ApprovalRequests {
    @NonNull
    private final EnrollmentRepository enrollmentRepository;
    @NonNull
    private final Clock clock;

    /** The device's newest request on the channel, in any state: bound to the device, not the session that made it. */
    public Optional<DeviceEnrollment> latestOf(AdmittedSession newDeviceSession) {
        return enrollmentRepository.findLatestApproval(
                newDeviceSession.customerId(),
                newDeviceSession.channel(),
                newDeviceSession.deviceId());
    }

    /** Stores a fresh request, or returns the one this restricted session already made (UQ_DE_CREATION). */
    public DeviceEnrollment create(DeviceEnrollment freshRequest, SessionId creationSessionId) {
        return enrollmentRepository.create(freshRequest, creationSessionId);
    }

    /** The customer's requests the primary device may still act on: waiting and not past their window. */
    public List<DeviceEnrollment> listOpenFor(AdmittedSession primaryDeviceSession) {
        Instant now = clock.instant();
        List<DeviceEnrollment> waitingRequests = enrollmentRepository.findOpenApprovals(
                primaryDeviceSession.customerId(),
                primaryDeviceSession.channel());
        return waitingRequests.stream()
                .filter(request -> request.isOpen(now))
                .toList();
    }

    /** The request the primary device names, when it is an approval request and still open, at whichever step. */
    public Optional<DeviceEnrollment> findOpen(EnrollmentId enrollmentId, AdmittedSession primaryDeviceSession) {
        Optional<DeviceEnrollment> found = enrollmentRepository.findApproval(
                enrollmentId,
                primaryDeviceSession.customerId(),
                primaryDeviceSession.channel());
        if (found.isEmpty()) {
            return Optional.empty();
        }
        DeviceEnrollment request = found.get();
        boolean openApproval = request.isApproval() && request.isOpen(clock.instant());
        if (!openApproval) {
            return Optional.empty();
        }
        return found;
    }

    /** The request the primary device names, when it is an approval request, still open and at this step. */
    public Optional<DeviceEnrollment> findOpenAt(EnrollmentId enrollmentId,
                                                 AdmittedSession primaryDeviceSession,
                                                 EnrollmentState step) {
        Optional<DeviceEnrollment> openRequest = findOpen(enrollmentId, primaryDeviceSession);
        if (openRequest.isEmpty() || openRequest.get().state() != step) {
            return Optional.empty();
        }
        return openRequest;
    }

    /** Writes the changed request over the version read; empty when another request changed it first. */
    public Optional<DeviceEnrollment> update(DeviceEnrollment changedRequest) {
        return enrollmentRepository.saveIfCurrent(changedRequest);
    }

    /** Writes a FAILED or EXPIRED request; one another request changed first is left to it. */
    public void close(DeviceEnrollment closedRequest) {
        enrollmentRepository.saveIfCurrent(closedRequest);
    }
}
