package com.vpbank.dcp.auth.application.port.out.model;

import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import java.time.Instant;
import java.util.Objects;
import lombok.Builder;

/**
 * The FACE transaction Auth asks MFA to open (DD 20 §5.2); the enrollment ID is the idempotent
 * {@code authOperationId}.
 */
@Builder
public record MfaTransactionRequest(CustomerId customerId, Channel channel, EnrollmentId authOperationId,
                                    Instant notAfter, String contextDigest) {
    public static final String PURPOSE = "TRUST_DEVICE";

    public MfaTransactionRequest {
        Objects.requireNonNull(customerId, "customerId");
        Objects.requireNonNull(channel, "channel");
        Objects.requireNonNull(authOperationId, "authOperationId");
        Objects.requireNonNull(notAfter, "notAfter");
        Objects.requireNonNull(contextDigest, "contextDigest");
    }
}
