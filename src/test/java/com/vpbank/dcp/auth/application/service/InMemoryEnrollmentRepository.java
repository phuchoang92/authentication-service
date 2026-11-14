package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.port.out.repository.EnrollmentRepository;
import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceEnrollment;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import com.vpbank.dcp.auth.domain.model.SessionId;
import java.time.Clock;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Enrollments with the adapter's contract: one per restricted session (idempotent create), CAS on version, and the
 * newest approval of a device found by the device (insertion order stands in for CREATED_AT).
 */
final class InMemoryEnrollmentRepository implements EnrollmentRepository {
    final Map<EnrollmentId, DeviceEnrollment> rows = new LinkedHashMap<>();
    final Map<SessionId, EnrollmentId> bySession = new HashMap<>();
    boolean unavailable;
    private final Clock clock;

    InMemoryEnrollmentRepository(Clock clock) {
        this.clock = clock;
    }

    @Override
    public ApprovalReservation reserveApproval(DeviceEnrollment fresh, SessionId sessionId, int maxPending) {
        check();
        Optional<DeviceEnrollment> open = findLatestApproval(fresh.customerId(), fresh.channel(), fresh.deviceId())
                .filter(request -> request.isOpen(clock.instant()));
        if (open.isPresent()) {
            return new ApprovalReservation.Reserved(open.get());
        }
        EnrollmentId existing = bySession.get(sessionId);
        if (existing != null) {
            return new ApprovalReservation.Reserved(rows.get(existing));
        }
        long waiting = findOpenApprovals(fresh.customerId(), fresh.channel()).stream()
                .filter(request -> request.isOpen(clock.instant())).count();
        if (waiting >= maxPending) {
            return new ApprovalReservation.QuotaReached();
        }
        rows.put(fresh.id(), fresh);
        bySession.put(sessionId, fresh.id());
        return new ApprovalReservation.Reserved(fresh);
    }

    @Override
    public Optional<DeviceEnrollment> saveIfCurrent(DeviceEnrollment changed) {
        check();
        DeviceEnrollment stored = rows.get(changed.id());
        if (stored == null || stored.version() != changed.version()) {
            return Optional.empty();
        }
        DeviceEnrollment saved = changed.withVersion(changed.version() + 1);
        rows.put(changed.id(), saved);
        return Optional.of(saved);
    }

    @Override
    public Optional<DeviceEnrollment> findLatestApproval(CustomerId customerId, Channel channel, DeviceId deviceId) {
        check();
        DeviceEnrollment latest = null;
        for (DeviceEnrollment enrollment : rows.values()) {
            boolean thisDevicesApproval = enrollment.isApproval()
                    && enrollment.customerId().equals(customerId)
                    && enrollment.channel() == channel
                    && enrollment.deviceId().equals(deviceId);
            if (thisDevicesApproval) {
                latest = enrollment;
            }
        }
        return Optional.ofNullable(latest);
    }

    @Override
    public Optional<DeviceEnrollment> findApproval(EnrollmentId id, CustomerId customerId, Channel channel) {
        check();
        return Optional.ofNullable(rows.get(id))
                .filter(e -> e.customerId().equals(customerId) && e.channel() == channel && e.isApproval());
    }

    @Override
    public List<DeviceEnrollment> findOpenApprovals(CustomerId customerId, Channel channel) {
        check();
        return rows.values().stream()
                .filter(e -> e.customerId().equals(customerId) && e.channel() == channel && e.isApproval() && e.state().open())
                .toList();
    }

    DeviceEnrollment only() {
        return rows.values().iterator().next();
    }

    private void check() {
        if (unavailable) {
            throw new RepositoryUnavailableException(new RuntimeException("down"));
        }
    }
}
