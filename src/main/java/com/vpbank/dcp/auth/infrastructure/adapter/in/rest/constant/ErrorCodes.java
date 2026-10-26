package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.constant;

/**
 * Every error code the API can return. Each one has a line in every {@code messages/errors_<lang>}
 * file; {@code ErrorCatalogueTest} keeps the two in step.
 */
public final class ErrorCodes {
    public static final String REQUEST_REJECTED = "REQUEST_REJECTED";
    public static final String IDENTITY_CONFLICT = "IDENTITY_CONFLICT";
    public static final String CUSTOMER_PROFILE_INCOMPLETE = "CUSTOMER_PROFILE_INCOMPLETE";
    public static final String ACCOUNT_CREATION_UNAVAILABLE = "ACCOUNT_CREATION_UNAVAILABLE";
    public static final String INVALID_CREDENTIALS = "INVALID_CREDENTIALS";
    public static final String ACCOUNT_NOT_READY = "ACCOUNT_NOT_READY";
    public static final String ACCOUNT_LOCKED = "ACCOUNT_LOCKED";
    public static final String CAPTCHA_REQUIRED = "CAPTCHA_REQUIRED";
    public static final String LOGIN_UNAVAILABLE = "LOGIN_UNAVAILABLE";
    public static final String SESSION_REQUIRED = "SESSION_REQUIRED";
    public static final String DEVICE_TRUST_REQUIRED = "DEVICE_TRUST_REQUIRED";
    public static final String DEVICE_KEY_REQUIRED = "DEVICE_KEY_REQUIRED";
    public static final String STATE_CONFLICT = "STATE_CONFLICT";
    public static final String WRONG_CHALLENGE = "WRONG_CHALLENGE";
    public static final String NO_USABLE_FACTOR = "NO_USABLE_FACTOR";
    public static final String MFA_NOT_PASSED = "MFA_NOT_PASSED";
    public static final String MFA_FAILED = "MFA_FAILED";
    public static final String MFA_EXPIRED = "MFA_EXPIRED";
    public static final String TOO_MANY_PENDING_DEVICES = "TOO_MANY_PENDING_DEVICES";
    public static final String NOT_PRIMARY_DEVICE = "NOT_PRIMARY_DEVICE";
    public static final String WRONG_AUTHORIZATION = "WRONG_AUTHORIZATION";
    public static final String AUTHORIZATION_EXPIRED = "AUTHORIZATION_EXPIRED";
    public static final String SESSION_GONE = "SESSION_GONE";
    public static final String SESSION_CONFLICT = "SESSION_CONFLICT";
    public static final String CUSTOMER_UNKNOWN = "CUSTOMER_UNKNOWN";
    public static final String INTERNAL_ERROR = "INTERNAL_ERROR";
    public static final String TEMPORARILY_UNAVAILABLE = "TEMPORARILY_UNAVAILABLE";

    private ErrorCodes() {
    }
}
