package com.vpbank.dcp.auth.infrastructure.config;

import com.vpbank.dcp.auth.application.port.out.repository.EnrollmentRepository;
import com.vpbank.dcp.auth.application.port.out.repository.TrustedDeviceRepository;
import com.vpbank.dcp.auth.domain.model.DevicePolicy;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.adapter.DeviceEnrollmentPersistenceAdapter;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.adapter.TrustedDevicePersistenceAdapter;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.common.DeviceIdProtection;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.DeviceEnrollmentJpaRepository;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.PrimaryTrustedDeviceJpaRepository;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.TrustedDeviceAuditJpaRepository;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.TrustedDeviceJpaRepository;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

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
        Map<String, byte[]> lookupKeys =
                decode(properties.lookupHmacKeysBase64(), "auth.device.lookup-hmac-keys-base64");
        Map<String, byte[]> encryptionKeys =
                decode(properties.encryptionKeysBase64(), "auth.device.encryption-keys-base64");
        try {
            return new DeviceIdProtection(
                    lookupKeys,
                    properties.lookupKeyId(),
                    encryptionKeys,
                    properties.encryptionKeyId(),
                    new SecureRandom());
        } catch (IllegalArgumentException invalid) {
            throw new IllegalStateException("auth.device.lookup-key-id / encryption-key-id: " + invalid.getMessage(), invalid);
        }
    }

    @Bean
    TrustedDeviceRepository trustedDeviceRepository(TrustedDeviceJpaRepository trustedDeviceJpaRepository,
                                                    PrimaryTrustedDeviceJpaRepository primaryTrustedDeviceJpaRepository,
                                                    TrustedDeviceAuditJpaRepository trustedDeviceAuditJpaRepository,
                                                    DeviceEnrollmentJpaRepository deviceEnrollmentJpaRepository,
                                                    DeviceIdProtection deviceIdProtection,
                                                    Clock clock) {
        return new TrustedDevicePersistenceAdapter(
                trustedDeviceJpaRepository,
                primaryTrustedDeviceJpaRepository,
                trustedDeviceAuditJpaRepository,
                deviceEnrollmentJpaRepository,
                deviceIdProtection,
                clock);
    }

    @Bean
    EnrollmentRepository enrollmentRepository(DeviceEnrollmentJpaRepository deviceEnrollmentJpaRepository,
                                              TrustedDeviceJpaRepository trustedDeviceJpaRepository,
                                              DeviceIdProtection deviceIdProtection,
                                              Clock clock) {
        return new DeviceEnrollmentPersistenceAdapter(
                deviceEnrollmentJpaRepository,
                trustedDeviceJpaRepository,
                deviceIdProtection,
                clock);
    }

    private static Map<String, byte[]> decode(Map<String, String> base64ByKeyId, String setting) {
        Map<String, byte[]> keys = new LinkedHashMap<>();
        base64ByKeyId.forEach((keyId, base64) -> {
            try {
                byte[] key = Base64.getDecoder().decode(base64);
                if (key.length < 32) {
                    throw new IllegalStateException(setting + "." + keyId + " must decode to at least 32 bytes");
                }
                keys.put(keyId, key);
            } catch (IllegalArgumentException invalid) {
                throw new IllegalStateException(setting + "." + keyId + " is not Base64", invalid);
            }
        });
        return keys;
    }
}
