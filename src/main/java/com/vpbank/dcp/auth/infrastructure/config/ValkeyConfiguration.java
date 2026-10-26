package com.vpbank.dcp.auth.infrastructure.config;

import com.vpbank.dcp.auth.application.port.out.gateway.OpaqueTokenGenerator;
import com.vpbank.dcp.auth.application.port.out.repository.CaptchaStore;
import com.vpbank.dcp.auth.application.port.out.repository.SessionStore;
import com.vpbank.dcp.auth.domain.model.SessionPolicy;
import com.vpbank.dcp.auth.infrastructure.adapter.out.valkey.CaptchaKeys;
import com.vpbank.dcp.auth.infrastructure.adapter.out.valkey.RandomOpaqueTokenGenerator;
import com.vpbank.dcp.auth.infrastructure.adapter.out.valkey.SessionKeys;
import com.vpbank.dcp.auth.infrastructure.adapter.out.valkey.ValkeyCaptchaStore;
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

    @Bean
    SessionStore sessionStore(StringRedisTemplate stringRedisTemplate, SessionKeys sessionKeys) {
        return new ValkeySessionAdapter(stringRedisTemplate, sessionKeys);
    }

    @Bean
    CaptchaStore captchaStore(StringRedisTemplate stringRedisTemplate, CaptchaProperties captchaProperties, Clock clock) {
        byte[] answerHmacKey = decodeKey(captchaProperties.answerHmacKeyBase64());
        CaptchaKeys captchaKeys = new CaptchaKeys(answerHmacKey);
        return new ValkeyCaptchaStore(stringRedisTemplate, captchaKeys, clock);
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
