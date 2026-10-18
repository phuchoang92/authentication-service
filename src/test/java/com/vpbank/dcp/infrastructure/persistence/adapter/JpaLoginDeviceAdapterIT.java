package com.vpbank.dcp.infrastructure.persistence.adapter;

import com.vpbank.dcp.core.domain.device.BindingId;
import com.vpbank.dcp.core.domain.customer.SubjectId;
import static org.assertj.core.api.Assertions.assertThat;

import com.vpbank.dcp.core.port.out.device.LoginDeviceRepository;
import com.vpbank.dcp.core.port.out.session.LoginSessionSecurityStore;
import com.vpbank.dcp.infrastructure.persistence.codec.DeviceIdCodec;
import com.vpbank.dcp.infrastructure.persistence.codec.DeviceIdKeyMaterial;
import com.vpbank.dcp.infrastructure.id.OpaqueBindingIdCodec;
import com.vpbank.dcp.infrastructure.persistence.codec.ProtectedDeviceId;
import com.vpbank.dcp.infrastructure.persistence.repository.LoginDevicePersistenceRepository;
import com.vpbank.dcp.infrastructure.persistence.repository.LoginSessionSecurityPersistenceRepository;
import com.vpbank.dcp.infrastructure.persistence.entity.SecurityAuditEventEntity;
import com.vpbank.dcp.infrastructure.persistence.repository.SecurityAuditJpaRepository;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.persistence.autoconfigure.EntityScan;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

@Testcontainers
@SpringBootTest(classes = JpaLoginDeviceAdapterIT.TestConfiguration.class,
        webEnvironment = SpringBootTest.WebEnvironment.NONE, properties = {
        "spring.jpa.hibernate.ddl-auto=none", "spring.datasource.hikari.maximum-pool-size=5",
        "spring.data.redis.host=127.0.0.1",
        "spring.data.redis.port=1", "spring.data.redis.username=none",
        "spring.data.redis.password=none", "spring.data.redis.ssl.enabled=false"
})
class JpaLoginDeviceAdapterIT {
    private static final String CHANNEL = "neo-mobile";
    private static final String INSTALLATION = "random-installation-123456789";

    @Container
    static final MySQLContainer<?> MYSQL = new MySQLContainer<>(DockerImageName.parse(
            "mysql@sha256:6ea90827b1100f8f2ae306a539f86d2c264a26ed435a2a9f75551dd5c3aeb242"))
            .withDatabaseName("auth_login_device")
            .withUsername("auth_test").withPassword("test-only-password");

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", MYSQL::getJdbcUrl);
        registry.add("spring.datasource.username", MYSQL::getUsername);
        registry.add("spring.datasource.password", MYSQL::getPassword);
    }

    @Autowired LoginDeviceRepository devices;
    @Autowired LoginSessionSecurityStore sessionSecurity;
    @Autowired DeviceIdCodec deviceIds;
    @Autowired OpaqueBindingIdCodec publicIds;
    @Autowired JdbcTemplate jdbc;

    @SpringBootConfiguration
    @EnableAutoConfiguration
    @EntityScan(basePackageClasses = SecurityAuditEventEntity.class)
    @EnableJpaRepositories(basePackageClasses = SecurityAuditJpaRepository.class)
    @Import({LoginDevicePersistenceRepository.class, LoginSessionSecurityPersistenceRepository.class})
    static class TestConfiguration {
        @Bean
        TransactionTemplate transactionTemplate(PlatformTransactionManager manager) {
            return new TransactionTemplate(manager);
        }

        @Bean
        DeviceIdCodec deviceIdCodec() {
            byte[] lookup = new byte[32];
            byte[] encryption = new byte[32];
            Arrays.fill(lookup, (byte) 7);
            Arrays.fill(encryption, (byte) 8);
            return new DeviceIdCodec(new DeviceIdKeyMaterial("lookup-test", Map.of("lookup-test", lookup)),
                    new DeviceIdKeyMaterial("encryption-test", Map.of("encryption-test", encryption)),
                    new SecureRandom());
        }

        @Bean
        OpaqueBindingIdCodec opaqueBindingIdCodec() {
            return new OpaqueBindingIdCodec();
        }

        @Bean
        LoginDeviceRepository loginDeviceRepository(LoginDevicePersistenceRepository repository,
                                                    DeviceIdCodec codec, OpaqueBindingIdCodec ids,
                                                    TransactionTemplate transactions) {
            return new JpaLoginDeviceAdapter(repository, codec, ids, transactions);
        }

        @Bean
        LoginSessionSecurityStore loginSessionSecurityStore(
                LoginSessionSecurityPersistenceRepository repository, TransactionTemplate transactions) {
            return new JpaLoginSessionSecurityStore(repository, transactions);
        }
    }

    @Test
    void currentDeviceRequiresOwnerChannelAndInstallation() {
        SubjectId subject = new SubjectId(UUID.randomUUID());
        BindingId bindingId = new BindingId(UUID.randomUUID());
        ProtectedDeviceId protectedId = deviceIds.protect(subject.value(), CHANNEL, bindingId.value(), INSTALLATION);
        seed(subject, bindingId, protectedId);
        String externalId = publicIds.encode(bindingId.value());

        assertThat(devices.current(subject, CHANNEL, INSTALLATION, externalId))
                .get().satisfies(device -> {
                    assertThat(device.primary()).isTrue();
                    assertThat(device.installationMatches()).isTrue();
                    assertThat(device.bindingId()).isEqualTo(bindingId);
                });
        assertThat(devices.current(subject, CHANNEL, "different-installation-123456", externalId))
                .get().satisfies(device -> assertThat(device.installationMatches()).isFalse());
        assertThat(devices.currentByBinding(subject, CHANNEL, INSTALLATION, bindingId))
                .get().satisfies(device -> assertThat(device.installationMatches()).isTrue());
        assertThat(devices.currentByBinding(new SubjectId(UUID.randomUUID()), CHANNEL, INSTALLATION, bindingId)).isEmpty();
        assertThat(devices.current(new SubjectId(UUID.randomUUID()), CHANNEL, INSTALLATION, externalId)).isEmpty();
        assertThat(devices.current(subject, "different-channel", INSTALLATION, externalId)).isEmpty();
        assertThat(devices.keyForProof(externalId)).isPresent();
        assertThat(devices.keyForProof(bindingId.value().toString())).isEmpty();
        assertThat(sessionSecurity.current(subject, bindingId, CHANNEL))
                .get().satisfies(security -> {
                    assertThat(security.customer().eligible()).isTrue();
                    assertThat(security.device().active()).isTrue();
                    assertThat(security.device().primary()).isTrue();
                    assertThat(security.customer().statusVersion()).isEqualTo(1);
                    // Distinct seeded values: proves each aliased column maps to its own
                    // component. Equal values would hide a swap between same-typed columns.
                    assertThat(security.versions().customerSecurityVersion()).isEqualTo(11);
                    assertThat(security.versions().credentialSecurityVersion()).isEqualTo(22);
                    assertThat(security.versions().deviceSecurityVersion()).isEqualTo(33);
                    assertThat(security.biometricEnabled()).isFalse();
                });
    }

    private void seed(SubjectId subject, BindingId bindingId, ProtectedDeviceId protectedId) {
        jdbc.update("""
                INSERT INTO auth_customer
                  (id, customer_id, customer_status_version, customer_security_version,
                   credential_security_version, customer_status_checked_at,
                   status, policy_version, created_at, updated_at)
                VALUES (UUID_TO_BIN(?), ?, 1, 11, 22, UTC_TIMESTAMP(6), 'ELIGIBLE', 'test',
                        UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
                """, subject.toString(), "customer-" + subject);
        jdbc.update("""
                INSERT INTO auth_trusted_device
                  (id, auth_customer_id, channel, device_id_lookup, device_id_lookup_key_id,
                   device_id_ciphertext, device_id_key_id, platform, label, status,
                   device_public_key, device_public_key_hash, device_key_algorithm,
                   trust_method, trust_policy_version, possession_assurance,
                   device_security_version,
                   trusted_at, expires_at, is_primary, created_at, updated_at)
                VALUES (UUID_TO_BIN(?), UUID_TO_BIN(?), ?, ?, ?, ?, ?, 'ANDROID',
                        'Test device', 'ACTIVE', X'01020304', UNHEX(SHA2(?, 256)),
                        'ES256', 'NFC_FACE_SMS_OTP', 'test-policy', 'MFA_KEY_POSSESSION',
                        33,
                        UTC_TIMESTAMP(6), UTC_TIMESTAMP(6) + INTERVAL 90 DAY, 1,
                        UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
                """, bindingId.toString(), subject.toString(), CHANNEL,
                protectedId.lookup().bytes(), protectedId.lookupKeyId(),
                protectedId.ciphertext(), protectedId.encryptionKeyId(), "public-key-" + bindingId);
    }
}
