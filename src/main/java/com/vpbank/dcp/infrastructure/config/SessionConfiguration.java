package com.vpbank.dcp.infrastructure.config;

import com.vpbank.dcp.core.domain.security.LookupKeyVersion;
import com.vpbank.dcp.core.port.out.session.SessionCryptography;
import com.vpbank.dcp.core.port.out.session.SessionAuthority;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.BankingTokenIssuer;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.BankingTokenEnvelopeIssuer;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.SessionCryptoAdapter;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.LengthPrefixedSigningInputEncoder;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.Sha256Digests;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.TokenLookupHasher;
import com.vpbank.dcp.infrastructure.adapter.out.redis.RedisSessionAuthority;
import com.vpbank.dcp.infrastructure.adapter.out.redis.RedisServerIdentity;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.AuthorityScope;
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
import java.util.Base64;

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
    LookupKeyVersion bankingLookupKeyVersion(NativeSessionProperties properties) {
        return new LookupKeyVersion(properties.lookupKeyVersion());
    }

    @Bean
    TokenLookupHasher bankingTokenLookupHasher(LookupKeyVersion version,
                                               NativeSessionProperties properties) {
        return new TokenLookupHasher(version, secret(properties.lookupHmacBase64()));
    }

    @Bean
    SecureRandom authenticationRandom() {
        return new SecureRandom();
    }

    @Bean
    SessionCryptography sessionCryptography(BankingTokenEnvelopeIssuer envelopes,
                                           LengthPrefixedSigningInputEncoder encoding,
                                           Sha256Digests digests, LookupKeyVersion version,
                                           TokenLookupHasher lookup, SecureRandom random) {
        return new SessionCryptoAdapter(new BankingTokenIssuer(version, random),
                lookup, envelopes, version, encoding, digests, random);
    }

    @Bean
    SessionDeliveryEscrowCodec sessionDeliveryEscrowCodec(JsonMapper json) {
        return new SessionDeliveryEscrowCodec(json);
    }

    @Bean
    SessionAuthority sessionAuthority(StringRedisTemplate redis,
                                      RedisServerIdentity identity, AuthorityScope scope,
                                      NativeSessionProperties properties, Clock clock) {
        return new RedisSessionAuthority(redis, identity, scope,
                Duration.ofMillis(properties.nonceValidityMs()), clock);
    }

    private byte[] secret(String encoded) {
        try {
            byte[] decoded = Base64.getDecoder().decode(encoded);
            if (decoded.length < 32) {
                throw new InvalidSessionRuntimeConfigurationException();
            }
            return decoded;
        } catch (IllegalArgumentException failure) {
            throw new InvalidSessionRuntimeConfigurationException(failure);
        }
    }
}
