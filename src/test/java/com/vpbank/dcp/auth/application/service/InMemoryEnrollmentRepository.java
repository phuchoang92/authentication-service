package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.port.out.repository.EnrollmentRepository;
import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceEnrollment;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import com.vpbank.dcp.auth.domain.model.SessionId;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** Enrollments with the adapter's contract: one per restricted session (idempotent create), CAS on version. */
final class InMemoryEnrollmentRepository implements EnrollmentRepository {
    final Map<EnrollmentId, DeviceEnrollment> rows = new HashMap<>();
    final Map<SessionId, EnrollmentId> bySession = new HashMap<>();
    boolean unavailable;

    @Override
    public DeviceEnrollment create(DeviceEnrollment fresh, SessionId sessionId) {
        check();
        EnrollmentId existing = bySession.get(sessionId);
        if (existing != null) {
            return rows.get(existing);
        }
        rows.put(fresh.id(), fresh);
        bySession.put(sessionId, fresh.id());
        return fresh;
    }

    @Override
    public Optional<DeviceEnrollment> find(EnrollmentId id, CustomerId customerId, DeviceId deviceId) {
        check();
        return Optional.ofNullable(rows.get(id)).filter(e -> e.customerId().equals(customerId) && e.deviceId().equals(deviceId));
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
    public Optional<DeviceEnrollment> findBySession(CustomerId customerId, DeviceId deviceId, SessionId sessionId) {
        check();
        EnrollmentId id = bySession.get(sessionId);
        if (id == null) {
            return Optional.empty();
        }
        return find(id, customerId, deviceId);
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
