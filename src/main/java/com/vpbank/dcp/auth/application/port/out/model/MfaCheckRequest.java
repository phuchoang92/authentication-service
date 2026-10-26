package com.vpbank.dcp.auth.application.port.out.model;

import com.vpbank.dcp.auth.domain.enums.EnrollmentPurpose;
import com.vpbank.dcp.auth.domain.enums.MfaFactor;
import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import java.util.List;
import java.util.Objects;
import lombok.Builder;

/**
 * What Auth asks MFA about an open transaction and what the signed receipt must be bound to
 * (DD 20 §5.4): the same purpose, factors and context digest the transaction was created with.
 */
@Builder
public record MfaCheckRequest(String mfaTransactionId, EnrollmentId authOperationId, EnrollmentPurpose purpose,
                              List<MfaFactor> factors, String contextDigest) {
    public MfaCheckRequest {
        Objects.requireNonNull(mfaTransactionId, "mfaTransactionId");
        Objects.requireNonNull(authOperationId, "authOperationId");
        Objects.requireNonNull(purpose, "purpose");
        Objects.requireNonNull(factors, "factors");
        Objects.requireNonNull(contextDigest, "contextDigest");
        if (factors.isEmpty()) {
            throw new IllegalArgumentException("At least one factor is required");
        }
        factors = List.copyOf(factors);
    }

    /** The receipt's {@code factor} claim: the factors joined with {@code +}, in request order (assumed contract). */
    public String factorClaim() {
        StringBuilder joined = new StringBuilder();
        for (MfaFactor factor : factors) {
            if (!joined.isEmpty()) {
                joined.append('+');
            }
            joined.append(factor.name());
        }
        return joined.toString();
    }
}
