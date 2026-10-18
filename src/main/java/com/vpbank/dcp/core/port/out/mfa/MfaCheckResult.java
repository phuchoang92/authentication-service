package com.vpbank.dcp.core.port.out.mfa;

/**
 * Whether the MFA service considers the transaction satisfied. Anything other than PASSED keeps
 * the login restricted; an MFA outage is {@link MfaUnavailableException}, never NOT_PASSED.
 */
public enum MfaCheckResult {
    PASSED,
    NOT_PASSED
}
