package com.vpbank.dcp.core.port.out.mfa;

import com.vpbank.dcp.core.domain.customer.SubjectId;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Auth re-checks the transaction it started. The owner and operation are sent again so the MFA
 * service can refuse a transaction that belongs to a different login.
 */
public record MfaCheck(String transactionId, UUID operationId, SubjectId owner, Instant now) {
    public MfaCheck {
        Objects.requireNonNull(operationId, "operationId");
        Objects.requireNonNull(owner, "owner");
        Objects.requireNonNull(now, "now");
        if (transactionId == null || !transactionId.matches("[A-Za-z0-9_-]{22,64}")) {
            throw new InvalidMfaTransactionException();
        }
    }
}
