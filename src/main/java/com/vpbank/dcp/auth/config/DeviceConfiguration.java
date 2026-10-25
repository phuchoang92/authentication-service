package com.vpbank.dcp.auth.config;

import com.vpbank.dcp.auth.adapter.out.persistence.adapter.TrustedDevicePersistenceAdapter;
import com.vpbank.dcp.auth.adapter.out.persistence.common.DeviceIdProtection;
import com.vpbank.dcp.auth.adapter.out.persistence.repository.PrimaryTrustedDeviceJpaRepository;
import com.vpbank.dcp.auth.adapter.out.persistence.repository.TrustedDeviceAuditJpaRepository;
import com.vpbank.dcp.auth.adapter.out.persistence.repository.TrustedDeviceJpaRepository;
import com.vpbank.dcp.auth.application.port.out.TrustedDeviceRepository;
import com.vpbank.dcp.auth.domain.model.DevicePolicy;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.SecureRandom;
import java.time.Clock;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/** Trusted devices (phase 3), active with login. Key material is validated here; the policy is handed on as plain Java. */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(prefix = "auth.login", name = "enabled", havingValue = "true")
@EnableConfigurationProperties(DeviceProperties.class)
public class DeviceConfiguration {

    @Bean
    DevicePolicy devicePolicy(DeviceProperties properties) {
        return new DevicePolicy(properties.trustDuration(), properties.maxLiveDevices(), properties.restrictedSessionTtl());
    }

    @Bean
    DeviceIdProtection deviceIdProtection(DeviceProperties properties) {
        try {
            return new DeviceIdProtection(decode(properties.lookupHmacKeysBase64(), "auth.device.lookup-hmac-keys-base64"),
                    properties.lookupKeyId(),
                    decode(properties.encryptionKeysBase64(), "auth.device.encryption-keys-base64"),
                    properties.encryptionKeyId(), new SecureRandom());
        } catch (IllegalArgumentException invalid) {
            throw new IllegalStateException("auth.device.lookup-key-id / encryption-key-id: " + invalid.getMessage(), invalid);
        }
    }

    @Bean
    TrustedDeviceRepository trustedDeviceRepository(TrustedDeviceJpaRepository devices,
                                                    PrimaryTrustedDeviceJpaRepository primaries,
                                                    TrustedDeviceAuditJpaRepository audit,
                                                    DeviceIdProtection protection, Clock clock) {
        return new TrustedDevicePersistenceAdapter(devices, primaries, audit, protection, clock);
    }

    private static Map<String, byte[]> decode(Map<String, String> base64ByKeyId, String setting) {
        Map<String, byte[]> keys = new LinkedHashMap<>();
        base64ByKeyId.forEach((id, base64) -> {
            try {
                byte[] key = Base64.getDecoder().decode(base64);
                if (key.length < 32) {
                    throw new IllegalStateException(setting + "." + id + " must decode to at least 32 bytes");
                }
                keys.put(id, key);
            } catch (IllegalArgumentException invalid) {
                throw new IllegalStateException(setting + "." + id + " is not Base64", invalid);
            }
        });
        return keys;
    }
}
