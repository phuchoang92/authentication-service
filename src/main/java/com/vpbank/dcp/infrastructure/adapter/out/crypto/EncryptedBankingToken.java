package com.vpbank.dcp.infrastructure.adapter.out.crypto;

import java.util.Objects;

/** Only this envelope and its signed receipt may cross the App-facing boundary. */
public record EncryptedBankingToken(String tokenEnvelope, String receipt) {

    public EncryptedBankingToken {
        Objects.requireNonNull(tokenEnvelope, "tokenEnvelope");
        Objects.requireNonNull(receipt, "receipt");
    }

    @Override
    public String toString() {
        return "EncryptedBankingToken[redacted]";
    }
}
