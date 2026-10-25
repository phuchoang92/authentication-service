package com.vpbank.dcp.infrastructure.config;

import com.vpbank.dcp.core.session.SessionCryptography;
import com.vpbank.dcp.core.session.SessionAuthority;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.BankingTokenIssuer;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.BankingTokenEnvelopeIssuer;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.SessionCryptoAdapter;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.LengthPrefixedSigningInputEncoder;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.Sha256Digests;
import com.vpbank.dcp.infrastructure.adapter.out.redis.RedisSessionAuthority;
import com.vpbank.dcp.infrastructure.adapter.out.redis.RedisServerIdentity;
import com.vpbank.dcp.infrastructure.config.properties.NativeSessionProperties;
import com.vpbank.dcp.infrastructure.persistence.codec.SessionDeliveryEscrowCodec;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.StringRedisTemplate;
import tools.jackson.databind.json.JsonMapper;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;

/** Assembles shared session issuance, authority and protected delivery mechanics. */
@Configuration(proxyBeanMethods = false)
@ConditionalOnWebApplication
@EnableConfigurationProperties(NativeSessionProperties.class)
public class SessionConfiguration {

    @Bean
    Clock authenticationClock() {
        return Clock.systemUTC();
    }

    @Bean
    SecureRandom authenticationRandom() {
        return new SecureRandom();
    }

    @Bean
    BankingTokenIssuer bankingTokenIssuer(SecureRandom random, Sha256Digests digests) {
        return new BankingTokenIssuer(random, digests);
    }

    @Bean
    SessionCryptography sessionCryptography(BankingTokenIssuer tokens,
                                           BankingTokenEnvelopeIssuer envelopes,
                                           LengthPrefixedSigningInputEncoder encoding,
                                           Sha256Digests digests, SecureRandom random) {
        return new SessionCryptoAdapter(tokens, envelopes, encoding, digests, random);
    }

    @Bean
    SessionDeliveryEscrowCodec sessionDeliveryEscrowCodec(JsonMapper json) {
        return new SessionDeliveryEscrowCodec(json);
    }

    @Bean
    SessionAuthority sessionAuthority(StringRedisTemplate redis, RedisServerIdentity identity,
                                      NativeSessionProperties properties, Clock clock) {
        return new RedisSessionAuthority(redis, identity,
                Duration.ofMillis(properties.nonceValidityMs()), clock);
    }
}
