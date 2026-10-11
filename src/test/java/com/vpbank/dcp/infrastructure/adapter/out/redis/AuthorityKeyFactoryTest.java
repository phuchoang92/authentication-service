package com.vpbank.dcp.infrastructure.adapter.out.redis;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.LookupKeyVersion;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.AuthorityScope;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.GuardKeys;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.InvalidAuthorityScopeException;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.SessionKeys;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.InvalidCryptographicInputException;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.ProofDigests;
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
        UUID id = UUID.randomUUID();
        GuardKeys guards = new GuardKeys(new AuthorityScope("bank-dev-neo"));
        assertThat(guards.forSubject(id)).isNotEqualTo(guards.forDevice(id));
        assertThat(guards.forSubject(id)).isNotEqualTo(
                new GuardKeys(new AuthorityScope("bank-prod-neo")).forSubject(id));

        Digest32 digest = Digest32.fromBytes(new byte[32]);
        SessionKeys sessions = new SessionKeys();
        assertThat(sessions.forLookup(new LookupKeyVersion("k1"), digest))
                .isNotEqualTo(sessions.forLookup(new LookupKeyVersion("k2"), digest));
        assertThat(sessions.forLookup(new LookupKeyVersion("k1"), digest))
                .startsWith("session:v1:k1:");
    }

    @Test
    void malformedUnicodeProofIdsCannotCollapseToTheSameDigest() {
        assertThatThrownBy(() -> new ProofDigests().ofProofId("\uD800"))
                .isInstanceOf(InvalidCryptographicInputException.class);
        assertThat(new ProofDigests().ofProofId("a:b"))
                .isNotEqualTo(new ProofDigests().ofProofId("a%3Ab"));
    }
}
