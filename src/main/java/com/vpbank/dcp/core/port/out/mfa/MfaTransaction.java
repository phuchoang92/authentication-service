package com.vpbank.dcp.core.port.out.mfa;

import java.time.Instant;
import java.util.Objects;

/** The identifier Auth stores and the App presents to the MFA service. Auth stores nothing else. */
public record MfaTransaction(String transactionId, Instant expiresAt) {
    public MfaTransaction {
        Objects.requireNonNull(expiresAt, "expiresAt");
        if (transactionId == null || !transactionId.matches("[A-Za-z0-9_-]{22,64}")) {
            throw new InvalidMfaTransactionException();
        }
    }
}
