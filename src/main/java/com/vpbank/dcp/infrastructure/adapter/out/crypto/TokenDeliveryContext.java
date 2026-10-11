package com.vpbank.dcp.infrastructure.adapter.out.crypto;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Frozen issuance inputs; a retry must reuse the escrowed envelope, not this factory. */
public record TokenDeliveryContext(UUID operationId, String appId, BankingTokenStatus status,
                                   String requestKeyThumbprint, String deviceKeyThumbprint,
                                   Instant tokenExpiresAt) {

    public TokenDeliveryContext {
        Objects.requireNonNull(operationId, "operationId");
        Objects.requireNonNull(appId, "appId");
        Objects.requireNonNull(status, "status");
        Objects.requireNonNull(requestKeyThumbprint, "requestKeyThumbprint");
        Objects.requireNonNull(tokenExpiresAt, "tokenExpiresAt");
        if (appId.isBlank() || requestKeyThumbprint.isBlank()) {
            throw new InvalidCryptographicInputException();
        }
    }
}
