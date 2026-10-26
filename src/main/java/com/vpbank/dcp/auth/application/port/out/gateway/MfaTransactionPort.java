package com.vpbank.dcp.auth.application.port.out.gateway;

import com.vpbank.dcp.auth.application.port.out.exception.PartnerUnavailableException;
import com.vpbank.dcp.auth.application.port.out.model.MfaCheckRequest;
import com.vpbank.dcp.auth.application.port.out.model.MfaTransactionRequest;
import java.time.Instant;

/**
 * The MFA service (DD 20 §5): open a FACE transaction after the device proved its key, and read its
 * outcome at confirm. {@code check} is read-only and may be repeated; Auth consumes the outcome.
 * Throws {@link PartnerUnavailableException} on 5xx/timeout; the service then changes nothing.
 */
public interface MfaTransactionPort {
    CreateResult create(MfaTransactionRequest request);

    CheckResult check(MfaCheckRequest request);

    sealed interface CreateResult {
        record Created(String mfaTransactionId, Instant expiresAt) implements CreateResult { }

        /** 422 NO_USABLE_FACTOR: the customer has no FACE enrolled. */
        record NoUsableFactor() implements CreateResult { }
    }

    sealed interface CheckResult {
        /** Signed receipt verified and bound to this enrollment; {@code receiptDigest} = SHA-256 of the compact JWS. */
        record Passed(String receiptDigest) implements CheckResult { }

        record Pending() implements CheckResult { }

        record Failed() implements CheckResult { }

        record Expired() implements CheckResult { }

        /** Bad signature or claims that do not match: never treated as pending. */
        record Rejected() implements CheckResult { }
    }
}
