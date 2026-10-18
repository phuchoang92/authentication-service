package com.vpbank.dcp.infrastructure.adapter.out.crypto;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class BankingTokenIssuerTest {
    private final BankingTokenIssuer issuer = new BankingTokenIssuer(new SecureRandom(), new Sha256Digests());

    @Test
    void tokenIsTheSessionIdAndARandomSecret() {
        UUID sessionId = UUID.randomUUID();
        var first = issuer.issue(sessionId);
        var second = issuer.issue(sessionId);

        assertThat(first.token().exactValue()).matches(sessionId + "\\.[A-Za-z0-9_-]{43}");
        assertThat(first.token().exactValue()).isNotEqualTo(second.token().exactValue());
        assertThat(first.token().toString()).isEqualTo("OpaqueBankingToken[redacted]");
    }

    /** Storage keeps only SHA-256 of the secret, so its data cannot rebuild the token. */
    @Test
    void secretDigestIsSha256OfTheSecretPartOnly() {
        var issued = issuer.issue(UUID.randomUUID());
        String secret = issued.token().exactValue().substring(37);

        assertThat(issued.secretDigest())
                .isEqualTo(new Sha256Digests().sha256(secret.getBytes(StandardCharsets.US_ASCII)));
        assertThat(issued.secretDigest().base64Url()).isNotEqualTo(secret);
    }
}
