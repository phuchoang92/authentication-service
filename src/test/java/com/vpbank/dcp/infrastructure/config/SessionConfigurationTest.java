package com.vpbank.dcp.infrastructure.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.vpbank.dcp.core.port.out.session.SessionAuthority;
import com.vpbank.dcp.core.port.out.session.SessionCryptography;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.BankingTokenEnvelopeIssuer;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.LengthPrefixedSigningInputEncoder;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.SessionCryptoAdapter;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.Sha256Digests;
import com.vpbank.dcp.infrastructure.adapter.out.redis.RedisServerIdentity;
import com.vpbank.dcp.infrastructure.adapter.out.redis.RedisSessionAuthority;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.AuthorityScope;
import com.vpbank.dcp.infrastructure.persistence.codec.SessionDeliveryEscrowCodec;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.data.redis.core.StringRedisTemplate;
import tools.jackson.databind.json.JsonMapper;

class SessionConfigurationTest {
    private final WebApplicationContextRunner context = new WebApplicationContextRunner()
            .withUserConfiguration(SessionConfiguration.class)
            .withBean(BankingTokenEnvelopeIssuer.class, () -> mock(BankingTokenEnvelopeIssuer.class))
            .withBean(LengthPrefixedSigningInputEncoder.class, LengthPrefixedSigningInputEncoder::new)
            .withBean(Sha256Digests.class, Sha256Digests::new)
            .withBean(JsonMapper.class, JsonMapper::new)
            .withBean(StringRedisTemplate.class, () -> mock(StringRedisTemplate.class))
            .withBean(RedisServerIdentity.class, () -> mock(RedisServerIdentity.class))
            .withBean(AuthorityScope.class, () -> new AuthorityScope("bank-session-config-test"))
            .withPropertyValues("auth.native-session.nonce-validity-ms=60000");

    @Test
    void assemblesSessionCryptographyAndAuthority() {
        context.run(started -> {
            assertThat(started).hasNotFailed()
                    .hasSingleBean(SessionCryptography.class).hasSingleBean(SessionAuthority.class)
                    .hasSingleBean(SessionDeliveryEscrowCodec.class);
            assertThat(started.getBean(SessionCryptography.class)).isInstanceOf(SessionCryptoAdapter.class);
            assertThat(started.getBean(SessionAuthority.class)).isInstanceOf(RedisSessionAuthority.class);
        });
    }
}
