package com.vpbank.dcp.auth.domain.enums;

/**
 * Why a login attempt or a service-token request ended the way it did (SECURITY_AUDIT_EVENT.REASON_CODE). Each reason belongs to
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
    PARTNER(SecurityEventType.LOGIN_UNAVAILABLE),
    /** A scoped service token was signed and handed to the calling service (slice 12). */
    TOKEN_ISSUED(SecurityEventType.SERVICE_TOKEN_ISSUED),
    /** The calling service is not granted the scope it asked for. */
    SCOPE_NOT_GRANTED(SecurityEventType.SERVICE_TOKEN_REFUSED),
    /** The scope binds the token to a business journey and the request named none. */
    BUSINESS_REFERENCE_MISSING(SecurityEventType.SERVICE_TOKEN_REFUSED);

    private final SecurityEventType type;

    SecurityEventReason(SecurityEventType type) {
        this.type = type;
    }

    public SecurityEventType type() {
        return type;
    }
}
