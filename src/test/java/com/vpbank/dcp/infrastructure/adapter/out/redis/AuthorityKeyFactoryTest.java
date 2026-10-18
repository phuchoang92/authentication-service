package com.vpbank.dcp.infrastructure.adapter.out.redis;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.AuthorityScope;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.InvalidAuthorityScopeException;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.SessionKeys;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.RuntimeKeys;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.InvalidCryptographicInputException;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.Sha256Digests;
import com.vpbank.dcp.core.domain.customer.SubjectId;
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

        SessionKeys sessions = new SessionKeys();
        UUID sessionId = UUID.fromString("11111111-1111-4111-8111-111111111111");
        SubjectId subject = new SubjectId(UUID.fromString("22222222-2222-4222-8222-222222222222"));
        assertThat(sessions.forSession(sessionId))
                .isEqualTo("session:v2:11111111-1111-4111-8111-111111111111");
        assertThat(sessions.forNonceFamily(sessionId))
                .isEqualTo("nonce:v2:11111111-1111-4111-8111-111111111111");
        assertThat(sessions.forSubjectSessions("neo-mobile", subject))
                .isEqualTo("subject-sessions:v1:neo-mobile:22222222-2222-4222-8222-222222222222");
    }

    /** The channel is a key segment: a separator inside it would let one list alias another. */
    @Test
    void channelThatIsNotAKeySafeCodeIsRefused() {
        SubjectId subject = new SubjectId(UUID.randomUUID());
        for (String channel : new String[] {"neo:mobile", "Neo-Mobile", "", "x".repeat(33)}) {
            assertThatThrownBy(() -> new SessionKeys().forSubjectSessions(channel, subject))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Test
    void malformedUnicodeProofIdsCannotCollapseToTheSameDigest() {
        assertThatThrownBy(() -> new Sha256Digests().ofProofId("\uD800"))
                .isInstanceOf(InvalidCryptographicInputException.class);
        assertThat(new Sha256Digests().ofProofId("a:b"))
                .isNotEqualTo(new Sha256Digests().ofProofId("a%3Ab"));
    }
}
