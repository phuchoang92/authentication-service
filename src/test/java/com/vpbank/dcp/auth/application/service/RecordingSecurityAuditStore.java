package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.port.out.model.SecurityAuditEvent;
import com.vpbank.dcp.auth.application.port.out.repository.SecurityAuditStore;
import java.util.ArrayList;
import java.util.List;

/** Test double: keeps every recorded event in order. */
final class RecordingSecurityAuditStore implements SecurityAuditStore {
    final List<SecurityAuditEvent> events = new ArrayList<>();

    @Override
    public void record(SecurityAuditEvent event) {
        events.add(event);
    }

    SecurityAuditEvent only() {
        if (events.size() != 1) {
            throw new AssertionError("expected exactly one audit event, got " + events.size());
        }
        return events.getFirst();
    }

    SecurityAuditEvent last() {
        return events.getLast();
    }
}
