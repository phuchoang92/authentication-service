package com.vpbank.dcp.auth.application.port.out.repository;

import com.vpbank.dcp.auth.application.port.out.model.SecurityAuditEvent;

/**
 * Sink of the security activity audit (SECURITY_AUDIT_EVENT).
 *
 * <p>Contract: {@link #record} <b>never blocks and never throws</b>. The event is handed over and the
 * caller moves on; the adapter writes it later and may drop it under overload. A service therefore
 * calls it after deciding, never inside a step whose outcome depends on it.
 */
public interface SecurityAuditStore {

    void record(SecurityAuditEvent event);
}
