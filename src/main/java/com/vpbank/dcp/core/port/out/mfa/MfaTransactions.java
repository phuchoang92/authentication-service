package com.vpbank.dcp.core.port.out.mfa;

/**
 * The MFA service owns every factor and every challenge. Auth starts one transaction and later
 * asks whether it passed; it never sees a code, a secret or a challenge.
 *
 * <p>Both calls throw {@link MfaUnavailableException} when the MFA service cannot answer. A
 * timeout is uncertain: the transaction may exist, so a start is never silently retried.
 */
public interface MfaTransactions {

    MfaStartResult start(MfaLoginRequest request);

    MfaCheckResult check(MfaCheck check);
}
