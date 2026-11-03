package com.vpbank.dcp.auth.domain.enums;

/**
 * What happened, for the security activity audit (SECURITY_AUDIT_EVENT.EVENT_TYPE). Activity, not a
 * state transition: device-trust transitions keep their own synchronous audit in TRUSTED_DEVICE_AUDIT.
 */
public enum SecurityEventType {
    /** A session was issued (full or restricted). */
    LOGIN_SUCCEEDED,
    /** The password or the user name was wrong. */
    LOGIN_FAILED,
    /** The attempt was turned away before the password was checked, or the account is not ready. */
    LOGIN_REFUSED,
    /** The database or a partner did not answer. */
    LOGIN_UNAVAILABLE,
    /** A scoped service token was issued to an internal service (slice 12). */
    SERVICE_TOKEN_ISSUED,
    /** An internal service asked for a token it may not have, or asked incompletely. */
    SERVICE_TOKEN_REFUSED;

    /** An event about an internal service, not a customer login: it names a service and a scope, no channel. */
    public boolean aboutAService() {
        return this == SERVICE_TOKEN_ISSUED || this == SERVICE_TOKEN_REFUSED;
    }
}
