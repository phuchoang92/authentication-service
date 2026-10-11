package com.vpbank.dcp.infrastructure.adapter.out.persistence.authority;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.vpbank.dcp.core.port.out.authority.AuthorityLeaseChange;
import com.vpbank.dcp.core.port.out.authority.AuthorityLeaseStore;
import com.vpbank.dcp.core.port.out.authority.LeaseChangeResult;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

@Testcontainers
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE, properties = {
        "server.ssl.enabled=false",
        "auth.authority.scope=bank-test-neo",
        "auth.ingress.external-origin=https://api.bank.test",
        "auth.ingress.allowed-workload-uris=spiffe://bank.test/mobile-bff",
        "spring.datasource.hikari.maximum-pool-size=10",
        "spring.data.redis.host=127.0.0.1",
        "spring.data.redis.port=1",
        "spring.data.redis.ssl.enabled=false"
})
class AuthorityLeaseMysqlIT {

    @Container
    static final MySQLContainer<?> MYSQL = new MySQLContainer<>(
            DockerImageName.parse("mysql@sha256:6ea90827b1100f8f2ae306a539f86d2c264a26ed435a2a9f75551dd5c3aeb242"))
            .withDatabaseName("auth_g1_test")
            .withUsername("auth_test")
            .withPassword("test-only-password");

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", MYSQL::getJdbcUrl);
        registry.add("spring.datasource.username", MYSQL::getUsername);
        registry.add("spring.datasource.password", MYSQL::getPassword);
    }

    @Autowired
    private JdbcTemplate jdbc;

    @Autowired
    private AuthorityLeaseStore store;

    @Autowired
    private TransactionTemplate transactions;

    @BeforeEach
    void freshControl() {
        jdbc.update("DELETE FROM auth_authority_control WHERE bank_scope = ?", "bank-test-neo");
        jdbc.update("""
                INSERT INTO auth_authority_control
                (bank_scope, generation, redis_run_id, state, controller_id, lease_until, fence, version, updated_at)
                VALUES (?, UNHEX(REPLACE(?, '-', '')), ?, 'READY',
                        UNHEX(REPLACE(?, '-', '')), UTC_TIMESTAMP(6) + INTERVAL 1 MINUTE,
                        7, 0, UTC_TIMESTAMP(6))
                """, "bank-test-neo", UUID.randomUUID().toString(), "run-before", UUID.randomUUID().toString());
    }

    @Test
    void migrationAndCasRequireExactVersionAndFence() {
        assertThat(jdbc.queryForObject("""
                SELECT COUNT(*) FROM information_schema.TABLES
                 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME REGEXP '^auth_'
                """, Integer.class)).isEqualTo(21);
        var change = change(0, 7, 8);
        LeaseChangeResult first = transactions.execute(status -> store.closeWithNewFence(change));
        LeaseChangeResult retry = transactions.execute(status -> store.closeWithNewFence(change));
        assertThat(first).isEqualTo(LeaseChangeResult.UPDATED);
        assertThat(retry).isEqualTo(LeaseChangeResult.STALE);
        assertThat(jdbc.queryForObject(
                "SELECT state FROM auth_authority_control WHERE bank_scope = ?",
                String.class, "bank-test-neo")).isEqualTo("CLOSED");
        assertThat(jdbc.queryForObject(
                "SELECT fence FROM auth_authority_control WHERE bank_scope = ?",
                Long.class, "bank-test-neo")).isEqualTo(8L);
    }

    @Test
    void mandatoryTransactionAndRollbackAreReal() {
        assertThatThrownBy(() -> store.closeWithNewFence(change(0, 7, 8)))
                .isInstanceOf(org.springframework.transaction.IllegalTransactionStateException.class);

        assertThatThrownBy(() -> transactions.execute(status -> {
            assertThat(store.closeWithNewFence(change(0, 7, 8)))
                    .isEqualTo(LeaseChangeResult.UPDATED);
            throw new ForcedRollbackException();
        })).isInstanceOf(ForcedRollbackException.class);
        assertThat(jdbc.queryForObject(
                "SELECT fence FROM auth_authority_control WHERE bank_scope = ?",
                Long.class, "bank-test-neo")).isEqualTo(7L);
    }

    @Test
    void concurrentControllersCannotBothAdvanceTheFence() throws Exception {
        var ready = new CountDownLatch(2);
        var release = new CountDownLatch(1);
        try (var workers = Executors.newFixedThreadPool(2)) {
            var first = workers.submit(() -> attemptConcurrentChange(ready, release));
            var second = workers.submit(() -> attemptConcurrentChange(ready, release));
            assertThat(ready.await(5, TimeUnit.SECONDS)).isTrue();
            release.countDown();
            assertThat(java.util.List.of(first.get(5, TimeUnit.SECONDS), second.get(5, TimeUnit.SECONDS)))
                    .containsExactlyInAnyOrder(LeaseChangeResult.UPDATED, LeaseChangeResult.STALE);
        }
    }

    @Test
    void schemaEnforcesUniqueCustomerAndIdentityOwnership() {
        String customerId = "customer-" + UUID.randomUUID();
        UUID firstSubject = UUID.randomUUID();
        insertSubject(firstSubject, customerId);
        assertThatThrownBy(() -> insertSubject(UUID.randomUUID(), customerId))
                .isInstanceOf(org.springframework.dao.DataIntegrityViolationException.class);

        assertThatThrownBy(() -> jdbc.update("""
                INSERT INTO auth_identity_link
                (id, subject_id, issuer, provider_subject, status, created_at)
                VALUES (UNHEX(REPLACE(?, '-', '')), UNHEX(REPLACE(?, '-', '')),
                        'https://issuer.bank.test', ?, 'ACTIVE', UTC_TIMESTAMP(6))
                """, UUID.randomUUID().toString(), UUID.randomUUID().toString(),
                "sub-" + UUID.randomUUID()))
                .isInstanceOf(org.springframework.dao.DataIntegrityViolationException.class);
    }

    @Test
    void compositeDeviceOwnershipAndLiveInstallationUniquenessAreDatabaseConstraints() {
        UUID subject = UUID.randomUUID();
        insertSubject(subject, "customer-" + UUID.randomUUID());
        jdbc.update("""
                INSERT INTO auth_subject_app
                (subject_id, app_id, status, version, created_at, updated_at)
                VALUES (UNHEX(REPLACE(?, '-', '')), 'neo-mobile', 'ACTIVE', 0,
                        UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
                """, subject.toString());
        String installation = UUID.randomUUID().toString();
        insertDeviceBinding(subject, "neo-mobile", installation);

        assertThatThrownBy(() -> insertDeviceBinding(subject, "neo-mobile", installation))
                .isInstanceOf(org.springframework.dao.DataIntegrityViolationException.class);
        assertThatThrownBy(() -> insertDeviceBinding(subject, "other-app", installation))
                .isInstanceOf(org.springframework.dao.DataIntegrityViolationException.class);
    }

    @Test
    void softwareKeyMigrationRejectsHardwareAssuranceClaim() {
        UUID subject = UUID.randomUUID();
        insertSubject(subject, "customer-" + UUID.randomUUID());
        jdbc.update("""
                INSERT INTO auth_subject_app
                (subject_id, app_id, status, version, created_at, updated_at)
                VALUES (UNHEX(REPLACE(?, '-', '')), 'neo-mobile', 'ACTIVE', 0,
                        UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
                """, subject.toString());

        assertThatThrownBy(() -> insertDeviceBinding(subject, "neo-mobile",
                UUID.randomUUID().toString(), "HARDWARE_KEY"))
                .isInstanceOf(org.springframework.dao.DataAccessException.class);
        insertDeviceBinding(subject, "neo-mobile", UUID.randomUUID().toString(), "NONE");
    }

    private LeaseChangeResult attemptConcurrentChange(CountDownLatch ready,
                                                       CountDownLatch release) throws Exception {
        ready.countDown();
        if (!release.await(5, TimeUnit.SECONDS)) {
            throw new IllegalStateException("Concurrent test barrier expired");
        }
        return transactions.execute(status -> store.closeWithNewFence(change(0, 7, 8)));
    }

    private void insertSubject(UUID id, String customerId) {
        jdbc.update("""
                INSERT INTO auth_subject
                (id, customer_id, customer_status_version, customer_last_block_version,
                 customer_status_checked_at, status, customer_security_version,
                 credential_security_version, policy_version, version, created_at, updated_at)
                VALUES (UNHEX(REPLACE(?, '-', '')), ?, 1, 0, UTC_TIMESTAMP(6),
                        'ELIGIBLE', 0, 0, 'test-policy', 0, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
                """, id.toString(), customerId);
    }

    private void insertDeviceBinding(UUID subjectId, String appId, String installation) {
        insertDeviceBinding(subjectId, appId, installation, "NONE");
    }

    private void insertDeviceBinding(UUID subjectId, String appId, String installation,
                                     String platformAssurance) {
        jdbc.update("""
                INSERT INTO auth_device_binding
                (id, subject_id, app_id, installation_hash, platform, label, status,
                 device_security_version, policy_version, possession_assurance,
                 platform_assurance, expires_at, version, created_at, updated_at)
                VALUES (UNHEX(REPLACE(?, '-', '')), UNHEX(REPLACE(?, '-', '')), ?,
                        UNHEX(SHA2(?, 256)), 'ANDROID', 'Test phone', 'PENDING_RESET',
                        0, 'test-policy', 'MFA_KEY_POSSESSION', ?,
                        UTC_TIMESTAMP(6) + INTERVAL 1 DAY, 0,
                        UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
                """, UUID.randomUUID().toString(), subjectId.toString(), appId, installation,
                platformAssurance);
    }

    private AuthorityLeaseChange change(long version, long fence, long nextFence) {
        return new AuthorityLeaseChange("bank-test-neo", version, fence, nextFence,
                UUID.randomUUID(), "run-after", UUID.randomUUID(), Instant.now().plusSeconds(60));
    }

    private static final class ForcedRollbackException extends RuntimeException {
    }
}
