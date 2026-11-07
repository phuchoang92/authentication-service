package com.vpbank.dcp.auth.application.port.out.model;

import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.EnrollmentPurpose;
import com.vpbank.dcp.auth.domain.enums.MfaFactor;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import java.time.Instant;
import java.util.List;
import lombok.Builder;
import lombok.NonNull;

/**
 * The transaction Auth asks MFA to open (DD 20 §5.2): the purpose names the flow, the factors the
 * customer must pass (FACE for the primary enrollment, FACE + OTP for approving a new device); the
 * enrollment ID is the idempotent {@code authOperationId}.
 */
@Builder
public record MfaTransactionRequest(@NonNull CustomerId customerId,
                                    @NonNull Channel channel,
                                    @NonNull EnrollmentId authOperationId,
                                    @NonNull EnrollmentPurpose purpose,
                                    @NonNull List<MfaFactor> factors,
                                    @NonNull Instant notAfter,
                                    @NonNull String contextDigest) {
    public MfaTransactionRequest {
        if (factors.isEmpty()) {
            throw new IllegalArgumentException("At least one factor is required");
        }
        factors = List.copyOf(factors);
    }
}
