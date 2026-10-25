package com.vpbank.dcp.infrastructure.adapter.out.crypto;

import com.vpbank.dcp.core.security.Digest32;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import java.util.UUID;

/**
 * Token = {@code <sessionId>.<secret>} with a 256-bit secret (draft doc 21 §2). Valkey is keyed
 * by the session ID and keeps only SHA-256 of the secret, so its data cannot rebuild a token.
 */
public final class BankingTokenIssuer {
    private static final int SECRET_BYTES = 32;

    private final SecureRandom random;
    private final Sha256Digests digests;

    public BankingTokenIssuer(SecureRandom random, Sha256Digests digests) {
        this.random = Objects.requireNonNull(random, "random");
        this.digests = Objects.requireNonNull(digests, "digests");
    }

    public IssuedBankingToken issue(UUID sessionId) {
        Objects.requireNonNull(sessionId, "sessionId");
        byte[] bytes = new byte[SECRET_BYTES];
        random.nextBytes(bytes);
        try {
            String secret = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
            return new IssuedBankingToken(new OpaqueBankingToken(sessionId + "." + secret),
                    digests.sha256(secret.getBytes(StandardCharsets.US_ASCII)));
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    /** The token for the App, and the only part of it that storage may keep. */
    public record IssuedBankingToken(OpaqueBankingToken token, Digest32 secretDigest) {
        public IssuedBankingToken {
            Objects.requireNonNull(token, "token");
            Objects.requireNonNull(secretDigest, "secretDigest");
        }

        @Override
        public String toString() {
            return "IssuedBankingToken[redacted]";
        }
    }
}
