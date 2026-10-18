package com.vpbank.dcp.core.port.out.mfa;

/**
 * The MFA service owns every factor and challenge (draft doc 20 §5). Auth starts one transaction
 * per trust and later asks whether it passed; it never sees a code, a face sample or a secret.
 *
 * <p>Both calls throw {@link MfaUnavailableException} when the MFA service cannot answer. Both
 * are safe to retry: {@code start} is idempotent on the Auth operation ID, {@code check} only reads.
 */
public interface MfaTransactions {

    MfaStartResult start(MfaTrustRequest request);

    MfaCheckResult check(MfaTrustCheck check);
}
