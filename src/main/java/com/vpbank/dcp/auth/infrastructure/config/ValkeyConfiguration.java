package com.vpbank.dcp.auth.infrastructure.config;

import com.vpbank.dcp.auth.application.port.out.gateway.OpaqueTokenGenerator;
import com.vpbank.dcp.auth.application.port.out.repository.CaptchaStore;
import com.vpbank.dcp.auth.application.port.out.repository.TransactionStore;
import com.vpbank.dcp.auth.application.port.out.repository.SessionStore;
import com.vpbank.dcp.auth.domain.model.SessionPolicy;
import com.vpbank.dcp.auth.infrastructure.adapter.out.valkey.BffAssertionKeys;
import com.vpbank.dcp.auth.infrastructure.adapter.out.valkey.CaptchaAnswerDigest;
import com.vpbank.dcp.auth.infrastructure.adapter.out.valkey.TransactionJsonCodec;
import com.vpbank.dcp.auth.infrastructure.adapter.out.valkey.TransactionKeys;
import com.vpbank.dcp.auth.infrastructure.adapter.out.valkey.RandomOpaqueTokenGenerator;
import com.vpbank.dcp.auth.infrastructure.adapter.out.valkey.SessionJsonCodec;
import com.vpbank.dcp.auth.infrastructure.adapter.out.valkey.SessionKeys;
import com.vpbank.dcp.auth.infrastructure.adapter.out.valkey.ValkeyAssertionReplayStore;
import com.vpbank.dcp.auth.infrastructure.adapter.out.valkey.CaptchaChallengeStore;
import com.vpbank.dcp.auth.infrastructure.adapter.out.valkey.ValkeyRecordCommands;
import com.vpbank.dcp.auth.infrastructure.adapter.out.valkey.ValkeyTransactionAdapter;
import com.vpbank.dcp.auth.infrastructure.adapter.out.valkey.ValkeySessionAdapter;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.Base64;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.StringRedisTemplate;

/**
 * Session authority on Valkey, active only with login ({@code auth.login.enabled=true}); the
 * connection itself comes from Spring Boot's {@code spring.data.redis.*}. The session key needs no
 * key material (slice 7); the CAPTCHA answer key is validated here and the plain
 * {@link SessionPolicy} is handed to the services (§12).
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(prefix = "auth.login", name = "enabled", havingValue = "true")
@EnableConfigurationProperties({SessionProperties.class, CaptchaProperties.class})
public class ValkeyConfiguration {

    @Bean
    SessionKeys sessionKeys() {
        return new SessionKeys();
    }

    /** Read and compare-and-set on one STRING key, one command each; shared by the session and transaction stores. */
    @Bean
    ValkeyRecordCommands valkeyRecordCommands(StringRedisTemplate stringRedisTemplate) {
        return new ValkeyRecordCommands(stringRedisTemplate);
    }

    @Bean
    SessionStore sessionStore(ValkeyRecordCommands valkeyRecordCommands, SessionKeys sessionKeys) {
        return new ValkeySessionAdapter(valkeyRecordCommands, sessionKeys, new SessionJsonCodec(SessionJsonCodec.strictJson()));
    }

    /** CAPTCHA challenges are one-shot transactions in the shared store; only the answer's HMAC key is theirs. */
    @Bean
    CaptchaStore captchaStore(TransactionStore transactionStore, CaptchaProperties captchaProperties, Clock clock) {
        byte[] answerHmacKey = decodeKey(captchaProperties.answerHmacKeyBase64());
        return new CaptchaChallengeStore(transactionStore, new CaptchaAnswerDigest(answerHmacKey), clock);
    }

    /** Transactions in flight (slice 11): one store for every flow, each flow bringing only its payload. */
    @Bean
    TransactionStore transactionStore(ValkeyRecordCommands valkeyRecordCommands) {
        TransactionJsonCodec transactionJsonCodec = new TransactionJsonCodec(TransactionJsonCodec.strictPayloadJson());
        return new ValkeyTransactionAdapter(valkeyRecordCommands, new TransactionKeys(), transactionJsonCodec);
    }

    /** Used BFF assertion IDs (slice 11): one SET NX per admitted trusted-device request. */
    @Bean
    ValkeyAssertionReplayStore valkeyAssertionReplayStore(StringRedisTemplate stringRedisTemplate, Clock clock) {
        return new ValkeyAssertionReplayStore(stringRedisTemplate, new BffAssertionKeys(), clock);
    }

    @Bean
    OpaqueTokenGenerator opaqueTokenGenerator() {
        return new RandomOpaqueTokenGenerator(new SecureRandom());
    }

    @Bean
    SessionPolicy sessionPolicy(SessionProperties properties) {
        return new SessionPolicy(properties.idle(), properties.absolute(), properties.maxAdmittedAtSkew());
    }

    private static byte[] decodeKey(String base64) {
        try {
            byte[] key = Base64.getDecoder().decode(base64);
            if (key.length < 32) {
                throw new IllegalStateException("auth.captcha.answer-hmac-key-base64 must decode to at least 32 bytes");
            }
            return key;
        } catch (IllegalArgumentException invalid) {
            throw new IllegalStateException("auth.captcha.answer-hmac-key-base64 is not Base64", invalid);
        }
    }
}
