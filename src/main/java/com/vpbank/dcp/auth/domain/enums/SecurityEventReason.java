package com.vpbank.dcp.auth.domain.enums;

/**
 * Why a login attempt ended the way it did (SECURITY_AUDIT_EVENT.REASON_CODE). Each reason belongs to
 * exactly one {@link SecurityEventType}, so a service names the reason and the type follows.
 */
public enum SecurityEventReason {
    /** A full ACTIVE session was issued. */
    FULL_SESSION(SecurityEventType.LOGIN_SUCCEEDED),
    /** A restricted NEED_TRUSTED_DEVICE session was issued. */
    RESTRICTED_SESSION(SecurityEventType.LOGIN_SUCCEEDED),
    /** The user name matched no identity. */
    UNKNOWN_USER(SecurityEventType.LOGIN_FAILED),
    /** The identity exists; the password (or the Keycloak identity) was wrong, and the failure was counted. */
    WRONG_PASSWORD(SecurityEventType.LOGIN_FAILED),
    /** The identity is locked, temporarily or permanently. */
    LOCKED(SecurityEventType.LOGIN_REFUSED),
    /** A solved CAPTCHA was required and missing or wrong. */
    CAPTCHA_REQUIRED(SecurityEventType.LOGIN_REFUSED),
    /** The password was right but the identity is not ACTIVE in Auth. */
    NOT_READY(SecurityEventType.LOGIN_REFUSED),
    /** The database or the session store did not answer. */
    REPOSITORY(SecurityEventType.LOGIN_UNAVAILABLE),
    /** Keycloak did not answer. */
    PARTNER(SecurityEventType.LOGIN_UNAVAILABLE);

    private final SecurityEventType type;

    SecurityEventReason(SecurityEventType type) {
        this.type = type;
    }

    public SecurityEventType type() {
        return type;
    }
}
