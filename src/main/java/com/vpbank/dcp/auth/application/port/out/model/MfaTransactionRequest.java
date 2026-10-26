package com.vpbank.dcp.auth.application.port.out.model;

import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.EnrollmentPurpose;
import com.vpbank.dcp.auth.domain.enums.MfaFactor;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import lombok.Builder;

/**
 * The transaction Auth asks MFA to open (DD 20 §5.2): the purpose names the flow, the factors the
 * customer must pass (FACE for the primary enrollment, FACE + OTP for approving a new device); the
 * enrollment ID is the idempotent {@code authOperationId}.
 */
@Builder
public record MfaTransactionRequest(CustomerId customerId, Channel channel, EnrollmentId authOperationId,
                                    EnrollmentPurpose purpose, List<MfaFactor> factors, Instant notAfter,
                                    String contextDigest) {
    public MfaTransactionRequest {
        Objects.requireNonNull(customerId, "customerId");
        Objects.requireNonNull(channel, "channel");
        Objects.requireNonNull(authOperationId, "authOperationId");
        Objects.requireNonNull(purpose, "purpose");
        Objects.requireNonNull(factors, "factors");
        Objects.requireNonNull(notAfter, "notAfter");
        Objects.requireNonNull(contextDigest, "contextDigest");
        if (factors.isEmpty()) {
            throw new IllegalArgumentException("At least one factor is required");
        }
        factors = List.copyOf(factors);
    }
}
