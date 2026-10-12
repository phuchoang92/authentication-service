package com.vpbank.dcp.infrastructure.adapter.out.redis;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.LookupKeyVersion;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.AuthorityScope;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.InvalidAuthorityScopeException;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.SessionKeys;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.RuntimeKeys;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.InvalidCryptographicInputException;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.Sha256Digests;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class AuthorityKeyFactoryTest {

    @Test
    void boundedScopeCannotInjectDelimiterOrUnicode() {
        assertThatThrownBy(() -> new AuthorityScope("bank:dev"))
                .isInstanceOf(InvalidAuthorityScopeException.class);
        assertThatThrownBy(() -> new AuthorityScope("ngân-hàng"))
                .isInstanceOf(InvalidAuthorityScopeException.class);
    }

    @Test
    void identityAndVersionDimensionsHaveUnambiguousKeys() {
        RuntimeKeys runtime = new RuntimeKeys(new AuthorityScope("bank-dev-neo"));
        assertThat(runtime.marker()).isNotEqualTo(
                new RuntimeKeys(new AuthorityScope("bank-prod-neo")).marker());

        Digest32 digest = Digest32.fromBytes(new byte[32]);
        SessionKeys sessions = new SessionKeys();
        assertThat(sessions.forLookup(new LookupKeyVersion("k1"), digest))
                .isNotEqualTo(sessions.forLookup(new LookupKeyVersion("k2"), digest));
        assertThat(sessions.forLookup(new LookupKeyVersion("k1"), digest))
                .startsWith("session:v1:k1:");
    }

    @Test
    void malformedUnicodeProofIdsCannotCollapseToTheSameDigest() {
        assertThatThrownBy(() -> new Sha256Digests().ofProofId("\uD800"))
                .isInstanceOf(InvalidCryptographicInputException.class);
        assertThat(new Sha256Digests().ofProofId("a:b"))
                .isNotEqualTo(new Sha256Digests().ofProofId("a%3Ab"));
    }
}
