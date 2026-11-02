package com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.adapter;

import com.vpbank.dcp.auth.application.port.out.model.SecurityAuditEvent;
import com.vpbank.dcp.auth.application.port.out.repository.SecurityAuditStore;

/** The store while {@code auth.audit.enabled} is false: events are accepted and forgotten. */
public final class DisabledSecurityAuditStore implements SecurityAuditStore {

    @Override
    public void record(SecurityAuditEvent event) {
        // Audit is switched off; nothing is kept.
    }
}
