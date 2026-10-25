package com.vpbank.dcp.infrastructure.persistence.adapter;

import static org.assertj.core.api.Assertions.assertThat;

import com.vpbank.dcp.core.customer.SubjectId;
import com.vpbank.dcp.core.device.BindingId;
import com.vpbank.dcp.core.security.Digest32;
import com.vpbank.dcp.core.trusteddevice.TrustActivation;
import com.vpbank.dcp.core.trusteddevice.TrustActivationResult;
import com.vpbank.dcp.core.customer.CustomerNumber;
import com.vpbank.dcp.core.session.KeyExchange;
import com.vpbank.dcp.core.session.LoginKeys;
import com.vpbank.dcp.core.session.PinnedCustomer;
import com.vpbank.dcp.core.session.PinnedDevice;
import com.vpbank.dcp.core.session.RestrictedSession;
import com.vpbank.dcp.core.session.TrustTarget;
import com.vpbank.dcp.core.session.WrappedServerKey;
import com.vpbank.dcp.infrastructure.persistence.codec.DeviceIdCodec;
import com.vpbank.dcp.infrastructure.persistence.codec.DeviceIdKeyMaterial;
import com.vpbank.dcp.infrastructure.persistence.codec.ProtectedDeviceId;
import com.vpbank.dcp.infrastructure.persistence.entity.SecurityAuditEventEntity;
import com.vpbank.dcp.infrastructure.persistence.repository.SecurityAuditJpaRepository;
import com.vpbank.dcp.infrastructure.persistence.repository.TrustedDeviceActivationPersistenceRepository;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
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
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
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
@SpringBootTest(classes = JpaTrustedDeviceRecordsIT.TestConfiguration.class,
        webEnvironment = SpringBootTest.WebEnvironment.NONE, properties = {
        "spring.datasource.hikari.maximum-pool-size=5",
        "spring.jpa.hibernate.ddl-auto=validate",
        "spring.data.redis.host=127.0.0.1", "spring.data.redis.port=1",
        "spring.data.redis.username=none", "spring.data.redis.password=none",
        "spring.data.redis.ssl.enabled=false"
})
class JpaTrustedDeviceRecordsIT {
    private static final String CHANNEL = "neo-mobile";

    @Container
    static final MySQLContainer<?> MYSQL = new MySQLContainer<>(DockerImageName.parse(
            "mysql@sha256:6ea90827b1100f8f2ae306a539f86d2c264a26ed435a2a9f75551dd5c3aeb242"))
            .withDatabaseName("auth_trust_activation")
            .withUsername("auth_test").withPassword("test-only-password");

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", MYSQL::getJdbcUrl);
        registry.add("spring.datasource.username", MYSQL::getUsername);
        registry.add("spring.datasource.password", MYSQL::getPassword);
    }

    @Autowired JpaTrustedDeviceRecords activation;
    @Autowired DeviceIdCodec deviceIds;
    @Autowired JdbcTemplate jdbc;

    @SpringBootConfiguration
    @EnableAutoConfiguration
    @EntityScan(basePackageClasses = SecurityAuditEventEntity.class)
    @EnableJpaRepositories(basePackageClasses = SecurityAuditJpaRepository.class)
    @Import(TrustedDeviceActivationPersistenceRepository.class)
    static class TestConfiguration {
        @Bean
        TransactionTemplate transactionTemplate(PlatformTransactionManager manager) {
            return new TransactionTemplate(manager);
        }

        @Bean
        DeviceIdCodec deviceIdCodec() {
            byte[] lookup = new byte[32];
            byte[] encryption = new byte[32];
            encryption[0] = 1;
            return new DeviceIdCodec(new DeviceIdKeyMaterial("lookup-test", Map.of("lookup-test", lookup)),
                    new DeviceIdKeyMaterial("encryption-test", Map.of("encryption-test", encryption)),
                    new SecureRandom());
        }

        @Bean
        JpaTrustedDeviceRecords trustedDeviceActivation(
                TrustedDeviceActivationPersistenceRepository devices, SecurityAuditJpaRepository audit,
                DeviceIdCodec deviceIds, TransactionTemplate transactions) {
            return new JpaTrustedDeviceRecords(devices, audit, deviceIds, transactions,
                    Clock.systemUTC(), new JpaTrustedDeviceRecords.TrustPolicy(
                            Duration.ofDays(90), 2, "MFA_FACE_KEY_EXCHANGE", "trust-test"));
        }
    }

    @Test
    void newDeviceBecomesTheTrustedPrimaryAndTheOldPrimaryLosesBiometricLogin() throws Exception {
        UUID customer = seedCustomer(1);
        UUID oldPrimary = seedDevice(customer, "old-device-id-0000001", key(), "ACTIVE", true);
        UUID biometric = seedBiometric(customer, oldPrimary);
        byte[] device = key();

        UUID activated = activated(newDevice(customer, 1, "new-device-id-0000001", device));

        assertThat(status(activated)).isEqualTo("ACTIVE");
        assertThat(primary(customer)).isEqualTo(activated);
        assertThat(jdbc.queryForObject("SELECT server_key_id FROM auth_trusted_device "
                + "WHERE id = UUID_TO_BIN(?)", String.class, activated.toString())).isEqualTo("w1");
        assertThat(jdbc.queryForMap("SELECT device_key_algorithm AS algorithm, "
                + "device_public_key AS public_key FROM auth_trusted_device WHERE id = UUID_TO_BIN(?)",
                activated.toString())).containsEntry("algorithm", "XWING-MLKEM768-X25519")
                .containsEntry("public_key", device);
        assertThat(status(oldPrimary)).isEqualTo("ACTIVE");
        assertThat(jdbc.queryForObject("SELECT status FROM auth_biometric_login WHERE id = UUID_TO_BIN(?)",
                String.class, biometric.toString())).isEqualTo("REVOKED");
        assertThat(eventTypes(customer)).containsExactly("DEVICE_TRUSTED", "PRIMARY_DEVICE_CHANGED");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM auth_security_audit_event "
                + "WHERE trusted_device_id = UUID_TO_BIN(?) AND mfa_receipt_digest IS NOT NULL",
                Integer.class, activated.toString())).isEqualTo(1);
    }

    /** V20: an X-Wing row must hold exactly a 1216-byte key; ES256 rows remain valid data. */
    @Test
    void xWingRowsMustHoldAWholeXWingKey() throws Exception {
        UUID customer = seedCustomer(1);
        UUID es256 = seedDevice(customer, "es256-device-id-00001", key(), "REVOKED", false);
        assertThat(jdbc.update("UPDATE auth_trusted_device SET device_key_algorithm = 'ES256', "
                + "device_public_key = ? WHERE id = UUID_TO_BIN(?)", new byte[91], es256.toString()))
                .isEqualTo(1);

        org.assertj.core.api.Assertions.assertThatThrownBy(() -> seedDevice(customer,
                        "short-key-device-id-01", new byte[1215], "ACTIVE", false))
                .hasMessageContaining("ck_trusted_device_key_algorithm");
    }

    /** A reinstalled App keeps its device ID but has a new key: the old binding is replaced. */
    @Test
    void reinstalledAppReplacesTheLiveBindingOfTheSameDeviceId() throws Exception {
        UUID customer = seedCustomer(1);
        UUID previous = seedDevice(customer, "same-device-id-000001", key(), "ACTIVE", true);

        UUID activated = activated(newDevice(customer, 1, "same-device-id-000001", key()));

        assertThat(activated).isNotEqualTo(previous);
        assertThat(status(previous)).isEqualTo("REVOKED");
        assertThat(jdbc.queryForObject("SELECT revoked_reason FROM auth_trusted_device "
                + "WHERE id = UUID_TO_BIN(?)", String.class, previous.toString())).isEqualTo("REPLACED");
        assertThat(primary(customer)).isEqualTo(activated);
        assertThat(eventTypes(customer))
                .containsExactly("DEVICE_REVOKED", "DEVICE_TRUSTED", "PRIMARY_DEVICE_CHANGED");
    }

    @Test
    void trustedNonPrimaryKeepsItsRowAndBecomesPrimary() throws Exception {
        UUID customer = seedCustomer(1);
        seedDevice(customer, "primary-device-000001", key(), "ACTIVE", true);
        byte[] kept = key();
        UUID other = seedDevice(customer, "other-device-0000001", kept, "ACTIVE", false);

        UUID activated = activated(known(customer, 1, other, kept, "other-device-0000001"));

        assertThat(activated).isEqualTo(other);
        assertThat(primary(customer)).isEqualTo(other);
        assertThat(eventTypes(customer)).containsExactly("PRIMARY_DEVICE_CHANGED");
    }

    /** One-way rows: a revoked device trusted again gets a new row with its kept key. */
    @Test
    void revokedDeviceIsTrustedAgainOnANewRowWithTheSameKey() throws Exception {
        UUID customer = seedCustomer(1);
        byte[] kept = key();
        UUID revoked = seedDevice(customer, "revoked-device-00001", kept, "REVOKED", false);

        UUID activated = activated(known(customer, 1, revoked, kept, "revoked-device-00001"));

        assertThat(activated).isNotEqualTo(revoked);
        assertThat(status(revoked)).isEqualTo("REVOKED");
        assertThat(status(activated)).isEqualTo("ACTIVE");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM auth_trusted_device "
                + "WHERE device_public_key_hash = ?", Integer.class,
                (Object) thumbprint(kept).bytes())).isEqualTo(2);
    }

    /** The customer changed after login: nothing is written, not even the primary switch. */
    @Test
    void changedCustomerStatusRejectsAndRollsBackEverything() throws Exception {
        UUID customer = seedCustomer(2);
        UUID primary = seedDevice(customer, "primary-device-000002", key(), "ACTIVE", true);

        assertThat(activation.activate(newDevice(customer, 1, "new-device-id-0000002", key())))
                .isInstanceOf(TrustActivationResult.Rejected.class);

        assertThat(primary(customer)).isEqualTo(primary);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM auth_trusted_device "
                + "WHERE auth_customer_id = UUID_TO_BIN(?)", Integer.class, customer.toString()))
                .isEqualTo(1);
        assertThat(eventTypes(customer)).isEmpty();
    }

    @Test
    void deviceLimitEvictsTheLeastRecentlyAuthenticatedDevice() throws Exception {
        UUID customer = seedCustomer(1);
        UUID oldest = seedDevice(customer, "device-oldest-000001", key(), "ACTIVE", false);
        UUID recent = seedDevice(customer, "device-recent-000001", key(), "ACTIVE", true);
        jdbc.update("UPDATE auth_trusted_device SET last_authenticated_at = UTC_TIMESTAMP(6) - INTERVAL 2 DAY "
                + "WHERE id = UUID_TO_BIN(?)", oldest.toString());
        jdbc.update("UPDATE auth_trusted_device SET last_authenticated_at = UTC_TIMESTAMP(6) - INTERVAL 1 HOUR "
                + "WHERE id = UUID_TO_BIN(?)", recent.toString());

        UUID activated = activated(newDevice(customer, 1, "device-newest-000001", key()));

        assertThat(status(oldest)).isEqualTo("REVOKED");
        assertThat(jdbc.queryForObject("SELECT revoked_reason FROM auth_trusted_device "
                + "WHERE id = UUID_TO_BIN(?)", String.class, oldest.toString())).isEqualTo("DEVICE_LIMIT");
        assertThat(status(recent)).isEqualTo("ACTIVE");
        assertThat(status(activated)).isEqualTo("ACTIVE");
    }

    /** Two live bindings can never share a key, even across customers. */
    @Test
    void keyAlreadyLiveOnAnotherBindingIsRejected() throws Exception {
        byte[] shared = key();
        seedDevice(seedCustomer(1), "victim-device-000001", shared, "ACTIVE", true);
        UUID attacker = seedCustomer(1);

        assertThat(activation.activate(newDevice(attacker, 1, "attacker-device-0001", shared)))
                .isInstanceOf(TrustActivationResult.Rejected.class);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM auth_trusted_device "
                + "WHERE auth_customer_id = UUID_TO_BIN(?)", Integer.class, attacker.toString()))
                .isZero();
    }

    private UUID activated(TrustActivation trust) {
        TrustActivationResult result = activation.activate(trust);
        assertThat(result).isInstanceOf(TrustActivationResult.Activated.class);
        return ((TrustActivationResult.Activated) result).bindingId().value();
    }

    private TrustActivation newDevice(UUID customer, long statusVersion, String deviceId, byte[] key)
            throws Exception {
        return activation(customer, statusVersion, new TrustTarget.NewDevice(), deviceId, key);
    }

    private TrustActivation known(UUID customer, long statusVersion, UUID binding, byte[] key,
                                  String deviceId) throws Exception {
        long securityVersion = jdbc.queryForObject("SELECT device_security_version FROM "
                + "auth_trusted_device WHERE id = UUID_TO_BIN(?)", Long.class, binding.toString());
        return activation(customer, statusVersion,
                new TrustTarget.KnownDevice(new BindingId(binding), thumbprint(key), securityVersion),
                deviceId, key);
    }

    private TrustActivation activation(UUID customer, long statusVersion, TrustTarget target,
                                       String deviceId, byte[] key) throws Exception {
        Digest32 placeholder = Digest32.fromBytes(new byte[32]);
        RestrictedSession login = new RestrictedSession(UUID.randomUUID(),
                new PinnedCustomer(new SubjectId(customer), new CustomerNumber("customer-" + customer),
                        statusVersion),
                new PinnedDevice(CHANNEL, "ANDROID", target),
                new LoginKeys("request-jwk", placeholder, "response-jwk"), UUID.randomUUID());
        KeyExchange exchange = new KeyExchange(serverKey(), "server-public-key", placeholder,
                text(key), thumbprint(key), UUID.randomUUID());
        return new TrustActivation(login, exchange, deviceId, receipt(),
                Instant.now().truncatedTo(ChronoUnit.MICROS));
    }

    private UUID seedCustomer(long statusVersion) {
        UUID customer = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO auth_customer (id, customer_id, customer_status_version,
                    customer_status_checked_at, status, policy_version, created_at, updated_at)
                VALUES (UUID_TO_BIN(?), ?, ?, UTC_TIMESTAMP(6), 'ELIGIBLE', 'test',
                        UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
                """, customer.toString(), "customer-" + customer, statusVersion);
        return customer;
    }

    private UUID seedDevice(UUID customer, String deviceId, byte[] key, String status, boolean primary)
            throws Exception {
        UUID binding = UUID.randomUUID();
        ProtectedDeviceId protectedId = deviceIds.protect(customer, CHANNEL, binding, deviceId);
        boolean revoked = "REVOKED".equals(status);
        jdbc.update("""
                INSERT INTO auth_trusted_device
                  (id, auth_customer_id, channel, device_id_lookup, device_id_lookup_key_id,
                   device_id_ciphertext, device_id_key_id, platform, label, status,
                   device_public_key, device_public_key_hash, device_key_algorithm,
                   trust_method, trust_policy_version, possession_assurance,
                   trusted_at, expires_at, revoked_at, revoked_reason, revoked_by_type,
                   revoked_by_id, is_primary, created_at, updated_at)
                VALUES (UUID_TO_BIN(?), UUID_TO_BIN(?), ?, ?, ?, ?, ?, 'ANDROID', 'Test device', ?,
                        ?, ?, 'XWING-MLKEM768-X25519', 'NFC_FACE_SMS_OTP', 'test-policy', 'MFA_KEY_POSSESSION',
                        UTC_TIMESTAMP(6), UTC_TIMESTAMP(6) + INTERVAL 90 DAY,
                        ?, ?, ?, ?, ?, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
                """, binding.toString(), customer.toString(), CHANNEL, protectedId.lookup().bytes(),
                protectedId.lookupKeyId(), protectedId.ciphertext(), protectedId.encryptionKeyId(),
                status, key, thumbprint(key).bytes(),
                revoked ? java.sql.Timestamp.from(Instant.now()) : null,
                revoked ? "LOST" : null, revoked ? "CUSTOMER" : null, revoked ? "test" : null,
                primary ? 1 : 0);
        return binding;
    }

    private UUID seedBiometric(UUID customer, UUID device) {
        UUID biometric = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO auth_biometric_login (id, trusted_device_id, auth_customer_id, channel,
                    credential_provider_id, provider_credential_id, provider_credential_version,
                    status, biometric_enforcement, registered_at, version)
                VALUES (UUID_TO_BIN(?), UUID_TO_BIN(?), UUID_TO_BIN(?), ?, 'keycloak', ?, 1,
                        'ACTIVE', 'CLIENT_ENFORCED', UTC_TIMESTAMP(6), 0)
                """, biometric.toString(), device.toString(), customer.toString(), CHANNEL,
                "credential-" + biometric);
        return biometric;
    }

    private String status(UUID binding) {
        return jdbc.queryForObject("SELECT status FROM auth_trusted_device WHERE id = UUID_TO_BIN(?)",
                String.class, binding.toString());
    }

    private UUID primary(UUID customer) {
        List<String> rows = jdbc.queryForList("SELECT BIN_TO_UUID(id) FROM auth_trusted_device "
                + "WHERE auth_customer_id = UUID_TO_BIN(?) AND is_primary = 1", String.class,
                customer.toString());
        return rows.isEmpty() ? null : UUID.fromString(rows.getFirst());
    }

    private List<String> eventTypes(UUID customer) {
        return jdbc.queryForList("SELECT event_type FROM auth_security_audit_event "
                + "WHERE auth_customer_id = UUID_TO_BIN(?) ORDER BY event_sequence", String.class,
                customer.toString());
    }

    /** Raw X-Wing public key bytes: persistence checks only their length and digest. */
    private static byte[] key() {
        byte[] raw = new byte[1216];
        new SecureRandom().nextBytes(raw);
        return raw;
    }

    private static String text(byte[] key) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(key);
    }

    private static Digest32 thumbprint(byte[] key) throws Exception {
        return Digest32.fromBytes(MessageDigest.getInstance("SHA-256").digest(key));
    }

    private static WrappedServerKey serverKey() {
        byte[] ciphertext = new byte[64];
        ciphertext[0] = 1;
        return new WrappedServerKey("w1", ciphertext);
    }

    private static Digest32 receipt() {
        byte[] digest = new byte[32];
        new SecureRandom().nextBytes(digest);
        return Digest32.fromBytes(digest);
    }
}
