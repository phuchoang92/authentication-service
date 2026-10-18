package com.vpbank.dcp.core.port.out.mfa;

import com.vpbank.dcp.core.domain.security.Digest32;
import java.util.Objects;

/** Read from a receipt the MFA service signed. An outage is an exception, never one of these. */
public sealed interface MfaCheckResult {

    /** {@code receiptDigest} is recorded in the trust audit event. */
    record Passed(Digest32 receiptDigest) implements MfaCheckResult {
        public Passed {
            Objects.requireNonNull(receiptDigest, "receiptDigest");
        }
    }

    /** Not finished yet: the App may elevate at the MFA service and confirm again. */
    record Pending() implements MfaCheckResult { }

    record Failed() implements MfaCheckResult { }

    record Expired() implements MfaCheckResult { }

    /** Bad signature, wrong claim set or claims that do not match this trust. Never Pending. */
    record InvalidReceipt() implements MfaCheckResult { }
}
