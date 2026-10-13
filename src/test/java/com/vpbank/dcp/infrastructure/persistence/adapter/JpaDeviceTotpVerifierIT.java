package com.vpbank.dcp.infrastructure.persistence.adapter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.vpbank.dcp.core.domain.device.DeviceOwnership;
import com.vpbank.dcp.core.domain.totp.TotpCode;
import com.vpbank.dcp.core.domain.totp.TotpVerificationPolicy;
import com.vpbank.dcp.core.port.out.totp.CheckDeviceTotp;
import com.vpbank.dcp.core.port.out.totp.DeviceTotpCheckResult;
import com.vpbank.dcp.core.port.out.totp.DeviceTotpUnavailableException;
import com.vpbank.dcp.infrastructure.adapter.out.totp.ProtectedTotpSecret;
import com.vpbank.dcp.infrastructure.adapter.out.totp.TotpAlgorithm;
import com.vpbank.dcp.infrastructure.adapter.out.totp.TotpSecretCodec;
import com.vpbank.dcp.infrastructure.adapter.out.totp.TotpSecretKeys;
import com.vpbank.dcp.infrastructure.persistence.repository.DeviceTotpPersistenceRepository;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.Duration;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

@Testcontainers
@SpringBootTest(classes = JpaDeviceTotpVerifierIT.TestConfiguration.class,
        webEnvironment = SpringBootTest.WebEnvironment.NONE, properties = {
        "spring.jpa.hibernate.ddl-auto=none", "spring.datasource.hikari.maximum-pool-size=5",
        "spring.data.redis.host=127.0.0.1", "spring.data.redis.port=1",
        "spring.data.redis.username=none", "spring.data.redis.password=none",
        "spring.data.redis.ssl.enabled=false"
})
class JpaDeviceTotpVerifierIT {
    private static final String CHANNEL = "neo-mobile";
    private static final byte[] SECRET = "12345678901234567890".getBytes(StandardCharsets.US_ASCII);
    private static final Instant NOW = Instant.ofEpochSecond(59);

    @Container
    static final MySQLContainer<?> MYSQL = new MySQLContainer<>(DockerImageName.parse(
            "mysql@sha256:6ea90827b1100f8f2ae306a539f86d2c264a26ed435a2a9f75551dd5c3aeb242"))
            .withDatabaseName("auth_device_totp")
            .withUsername("auth_test").withPassword("test-only-password");

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", MYSQL::getJdbcUrl);
        registry.add("spring.datasource.username", MYSQL::getUsername);
        registry.add("spring.datasource.password", MYSQL::getPassword);
    }

    @SpringBootConfiguration
    @EnableAutoConfiguration
    @Import(DeviceTotpPersistenceRepository.class)
    static class TestConfiguration {
        @Bean
        TransactionTemplate transactionTemplate(PlatformTransactionManager manager) {
            return new TransactionTemplate(manager);
        }

        @Bean
        TotpSecretCodec totpSecretCodec() {
            return new TotpSecretCodec(new TotpSecretKeys("test-key",
                    Map.of("test-key", new byte[32])), new SecureRandom());
        }

        @Bean
        JpaDeviceTotpVerifier verifier(DeviceTotpPersistenceRepository repository,
                                       TotpSecretCodec codec, TransactionTemplate transaction) {
            return new JpaDeviceTotpVerifier(repository, codec, new TotpAlgorithm(),
                    new TotpVerificationPolicy(3, Duration.ofMinutes(10)),
                    Clock.fixed(NOW, ZoneOffset.UTC), transaction);
        }
    }

    @Autowired JpaDeviceTotpVerifier verifier;
    @Autowired TotpSecretCodec codec;
    @Autowired JdbcTemplate jdbc;

    @Test
    void acceptsOnceAndRejectsReplayAndWrongOwner() {
        Fixture fixture = seed();
        try (TotpCode code = code()) {
            CheckDeviceTotp check = fixture.check(code);
            assertThat(verifier.verify(check)).isEqualTo(DeviceTotpCheckResult.ACCEPTED);
            assertThat(verifier.verify(check)).isEqualTo(DeviceTotpCheckResult.REJECTED);
            assertThat(verifier.verify(new CheckDeviceTotp(
                    new DeviceOwnership(UUID.randomUUID(), CHANNEL), fixture.deviceId(), code)))
                    .isEqualTo(DeviceTotpCheckResult.REJECTED);
        }
    }

    @Test
    void revokedDeviceCannotUseCredential() {
        Fixture fixture = seed();
        jdbc.update("UPDATE auth_trusted_device SET status = 'REVOKED', revoked_at = UTC_TIMESTAMP(6), "
                + "revoked_reason = 'LOST', revoked_by_type = 'CUSTOMER', revoked_by_id = 'test' "
                + "WHERE id = UUID_TO_BIN(?)", fixture.deviceId().toString());
        try (TotpCode code = code()) {
            assertThat(verifier.verify(fixture.check(code))).isEqualTo(DeviceTotpCheckResult.REJECTED);
        }
    }

    @Test
    void revokedCredentialAndWrongChannelAreRejected() {
        Fixture fixture = seed();
        try (TotpCode code = code()) {
            assertThat(verifier.verify(new CheckDeviceTotp(
                    new DeviceOwnership(fixture.customerId(), "other-channel"),
                    fixture.deviceId(), code))).isEqualTo(DeviceTotpCheckResult.REJECTED);
            jdbc.update("UPDATE auth_device_totp_credential SET status = 'REVOKED', "
                    + "revoked_at = UTC_TIMESTAMP(6) WHERE trusted_device_id = UUID_TO_BIN(?)",
                    fixture.deviceId().toString());
            assertThat(verifier.verify(fixture.check(code))).isEqualTo(DeviceTotpCheckResult.REJECTED);
        }
    }

    @Test
    void databaseAllowsOnlyOneActiveCredentialPerDevice() {
        Fixture fixture = seed();
        UUID nextCredentialId = UUID.randomUUID();
        ProtectedTotpSecret next = codec.protect(fixture.customerId(), CHANNEL,
                fixture.deviceId(), nextCredentialId, SECRET);
        assertThatThrownBy(() -> jdbc.update("""
                INSERT INTO auth_device_totp_credential
                  (id, trusted_device_id, secret_ciphertext, secret_key_id, status, activated_at)
                VALUES (UUID_TO_BIN(?), UUID_TO_BIN(?), ?, ?, 'ACTIVE', UTC_TIMESTAMP(6))
                """, nextCredentialId.toString(), fixture.deviceId().toString(),
                next.ciphertext(), next.keyId()))
                .isInstanceOf(org.springframework.dao.DataIntegrityViolationException.class);
    }

    @Test
    void concurrentUseAcceptsAtMostOne() throws Exception {
        Fixture fixture = seed();
        CountDownLatch start = new CountDownLatch(1);
        Callable<DeviceTotpCheckResult> attempt = () -> {
            start.await();
            try (TotpCode code = code()) {
                return verifier.verify(fixture.check(code));
            }
        };
        try (var executor = Executors.newFixedThreadPool(2)) {
            var first = executor.submit(attempt);
            var second = executor.submit(attempt);
            start.countDown();
            assertThat(java.util.List.of(first.get(), second.get()))
                    .containsExactlyInAnyOrder(DeviceTotpCheckResult.ACCEPTED,
                            DeviceTotpCheckResult.REJECTED);
        }
    }

    @Test
    void tamperedSecretFailsClosed() {
        Fixture fixture = seed();
        jdbc.update("UPDATE auth_device_totp_credential SET secret_ciphertext = X'010203' "
                + "WHERE trusted_device_id = UUID_TO_BIN(?)", fixture.deviceId().toString());
        try (TotpCode code = code()) {
            assertThatThrownBy(() -> verifier.verify(fixture.check(code)))
                    .isInstanceOf(DeviceTotpUnavailableException.class);
        }
    }

    @Test
    void repeatedWrongCodesLockCredentialAcrossRequests() {
        Fixture fixture = seed();
        for (int attempt = 0; attempt < 3; attempt++) {
            try (TotpCode wrong = new TotpCode("000000".toCharArray())) {
                assertThat(verifier.verify(fixture.check(wrong)))
                        .isEqualTo(DeviceTotpCheckResult.REJECTED);
            }
        }
        Integer failureCount = jdbc.queryForObject("SELECT failed_attempts FROM auth_device_totp_credential "
                + "WHERE trusted_device_id = UUID_TO_BIN(?)", Integer.class,
                fixture.deviceId().toString());
        assertThat(failureCount).isZero();
        assertThat(jdbc.queryForObject("SELECT blocked_until FROM auth_device_totp_credential "
                + "WHERE trusted_device_id = UUID_TO_BIN(?)", java.sql.Timestamp.class,
                fixture.deviceId().toString())).isNotNull();
        try (TotpCode correct = code()) {
            assertThat(verifier.verify(fixture.check(correct)))
                    .isEqualTo(DeviceTotpCheckResult.REJECTED);
        }
    }

    private Fixture seed() {
        UUID customerId = UUID.randomUUID();
        UUID deviceId = UUID.randomUUID();
        UUID credentialId = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO auth_customer
                  (id, customer_id, customer_status_version, customer_status_checked_at,
                   status, policy_version, created_at, updated_at)
                VALUES (UUID_TO_BIN(?), ?, 1, UTC_TIMESTAMP(6), 'ELIGIBLE', 'test',
                        UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
                """, customerId.toString(), "customer-" + customerId);
        jdbc.update("""
                INSERT INTO auth_trusted_device
                  (id, auth_customer_id, channel, device_id_lookup, device_id_lookup_key_id,
                   device_id_ciphertext, device_id_key_id, platform, label, status,
                   device_public_key, device_public_key_hash, device_key_algorithm,
                   trust_method, trust_policy_version, possession_assurance,
                   trusted_at, expires_at, created_at, updated_at)
                VALUES (UUID_TO_BIN(?), UUID_TO_BIN(?), ?, UNHEX(SHA2(?, 256)),
                        'test-lookup-key', X'010203', 'test-encryption-key', 'ANDROID',
                        'Test device', 'ACTIVE', X'01020304', UNHEX(SHA2(?, 256)),
                        'ES256', 'NFC_FACE_SMS_OTP', 'test-policy', 'MFA_KEY_POSSESSION',
                        UTC_TIMESTAMP(6), UTC_TIMESTAMP(6) + INTERVAL 90 DAY,
                        UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
                """, deviceId.toString(), customerId.toString(), CHANNEL,
                "installation-" + deviceId, "public-key-" + deviceId);
        ProtectedTotpSecret stored = codec.protect(customerId, CHANNEL, deviceId, credentialId, SECRET);
        jdbc.update("""
                INSERT INTO auth_device_totp_credential
                  (id, trusted_device_id, secret_ciphertext, secret_key_id, status, activated_at)
                VALUES (UUID_TO_BIN(?), UUID_TO_BIN(?), ?, ?, 'ACTIVE', UTC_TIMESTAMP(6))
                """, credentialId.toString(), deviceId.toString(), stored.ciphertext(), stored.keyId());
        return new Fixture(customerId, deviceId);
    }

    private static TotpCode code() {
        // RFC 6238 SHA-1 vector truncated from eight digits to this six-digit profile.
        return new TotpCode("287082".toCharArray());
    }

    private record Fixture(UUID customerId, UUID deviceId) {
        CheckDeviceTotp check(TotpCode code) {
            return new CheckDeviceTotp(new DeviceOwnership(customerId, CHANNEL), deviceId, code);
        }
    }
}
