package com.vpbank.dcp.infrastructure.adapter.out.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.vpbank.dcp.core.domain.security.LookupKeyVersion;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.SessionKeys;
import java.security.SecureRandom;
import org.junit.jupiter.api.Test;

class BankingTokenIssuerTest {

    @Test
    void tokenIsRandomRedactedAndNeverUsedAsRedisLookupKey() {
        var version = new LookupKeyVersion("k1");
        var issuer = new BankingTokenIssuer(version, new SecureRandom());
        var first = issuer.issue();
        var second = issuer.issue();
        byte[] secret = new byte[32];
        java.util.Arrays.fill(secret, (byte) 5);

        try (var hasher = new TokenLookupHasher(version, secret)) {
            String lookup = new SessionKeys().forLookup(version, hasher.digest(first.exactValue()));
            assertTrue(first.exactValue().matches("k1\\.[A-Za-z0-9_-]{43}"));
            assertNotEquals(first.exactValue(), second.exactValue());
            assertEquals("OpaqueBankingToken[redacted]", first.toString());
            assertTrue(lookup.startsWith("session:v1:k1:"));
            assertTrue(!lookup.contains(first.exactValue()));
        }
    }
}
