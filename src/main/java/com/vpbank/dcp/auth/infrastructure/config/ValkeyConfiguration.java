package com.vpbank.dcp.auth.infrastructure.config;

import com.vpbank.dcp.auth.infrastructure.adapter.out.valkey.CaptchaKeys;
import com.vpbank.dcp.auth.infrastructure.adapter.out.valkey.RandomOpaqueTokenGenerator;
import com.vpbank.dcp.auth.infrastructure.adapter.out.valkey.ValkeyCaptchaStore;
import com.vpbank.dcp.auth.infrastructure.adapter.out.valkey.SessionKeys;
import com.vpbank.dcp.auth.infrastructure.adapter.out.valkey.ValkeySessionAdapter;
import com.vpbank.dcp.auth.application.port.out.repository.CaptchaStore;
import com.vpbank.dcp.auth.application.port.out.gateway.OpaqueTokenGenerator;
import com.vpbank.dcp.auth.application.port.out.repository.SessionStore;
import com.vpbank.dcp.auth.domain.model.SessionPolicy;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Session authority on Valkey, active only with login ({@code auth.login.enabled=true}); the
 * connection itself comes from Spring Boot's {@code spring.data.redis.*}. The HMAC keys are
 * validated here and the plain {@link SessionPolicy} is handed to the services (§12).
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(prefix = "auth.login", name = "enabled", havingValue = "true")
@EnableConfigurationProperties(SessionProperties.class)
public class ValkeyConfiguration {

    @Bean
    SessionKeys sessionKeys(SessionProperties properties) {
        Map<String, byte[]> keys = new LinkedHashMap<>();
        properties.lookupHmacKeysBase64().forEach((version, base64) -> keys.put(version, decodeKey(version, base64)));
        if (!keys.containsKey(properties.lookupKeyVersion())) {
            throw new IllegalStateException("auth.session.lookup-key-version " + properties.lookupKeyVersion()
                    + " has no entry in auth.session.lookup-hmac-keys-base64");
        }
        return new SessionKeys(keys);
    }

    @Bean
    SessionStore sessionStore(StringRedisTemplate redis, SessionKeys keys) {
        return new ValkeySessionAdapter(redis, keys);
    }

    /** CAPTCHA answers are HMAC-ed with the current session lookup key: one secret to manage. */
    @Bean
    CaptchaStore captchaStore(StringRedisTemplate redis, SessionProperties properties, java.time.Clock clock) {
        String base64 = properties.lookupHmacKeysBase64().get(properties.lookupKeyVersion());
        if (base64 == null) {
            throw new IllegalStateException("auth.session.lookup-key-version " + properties.lookupKeyVersion()
                    + " has no entry in auth.session.lookup-hmac-keys-base64");
        }
        return new ValkeyCaptchaStore(redis, new CaptchaKeys(decodeKey(properties.lookupKeyVersion(), base64)), clock);
    }

    @Bean
    OpaqueTokenGenerator opaqueTokenGenerator(SessionProperties properties) {
        return new RandomOpaqueTokenGenerator(new SecureRandom(), properties.lookupKeyVersion());
    }

    @Bean
    SessionPolicy sessionPolicy(SessionProperties properties) {
        return new SessionPolicy(properties.idle(), properties.absolute(), properties.maxAdmittedAtSkew());
    }

    private static byte[] decodeKey(String version, String base64) {
        try {
            byte[] key = Base64.getDecoder().decode(base64);
            if (key.length < 32) {
                throw new IllegalStateException("auth.session.lookup-hmac-keys-base64." + version
                        + " must decode to at least 32 bytes");
            }
            return key;
        } catch (IllegalArgumentException invalid) {
            throw new IllegalStateException("auth.session.lookup-hmac-keys-base64." + version + " is not Base64", invalid);
        }
    }
}
