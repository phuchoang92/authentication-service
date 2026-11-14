package com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.adapter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.vpbank.dcp.auth.application.command.RouteAfterPasswordCommand;
import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.port.out.model.DeviceRevocation;
import com.vpbank.dcp.auth.application.port.out.repository.TrustedDeviceRepository;
import com.vpbank.dcp.auth.application.port.out.repository.TrustedDeviceRevocationStore;
import com.vpbank.dcp.auth.application.port.out.repository.TrustedDeviceRevocationStore.RevocationCommit;
import com.vpbank.dcp.auth.application.service.TrustedDeviceService;
import com.vpbank.dcp.auth.application.service.TrustedDeviceService.DeviceRouting;
import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.DevicePlatform;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.DeviceInstallation;
import com.vpbank.dcp.auth.domain.model.DevicePolicy;
import com.vpbank.dcp.auth.domain.model.DomainFixtures;
import com.vpbank.dcp.auth.domain.model.TrustedDevice;
import com.vpbank.dcp.auth.domain.model.TrustedDeviceId;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.common.DeviceIdProtection;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.entity.TrustedDeviceAuditEntity;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.entity.TrustedDeviceEntity;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.mapper.TrustedDevicePersistenceMapper;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.PrimaryTrustedDeviceJpaRepository;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.TrustedDeviceAuditJpaRepository;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.TrustedDeviceJpaRepository;
import com.vpbank.dcp.auth.infrastructure.config.DeviceConfiguration;
import com.vpbank.dcp.auth.infrastructure.config.JpaConfiguration;
import jakarta.persistence.EntityManagerFactory;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import org.hibernate.SessionFactory;
import org.hibernate.stat.Statistics;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/** Protected bindings, login query count and revoke transactions on MySQL. */
@Testcontainers
@DataJpaTest(properties = {"spring.jpa.hibernate.ddl-auto=validate", "spring.flyway.enabled=true", "auth.login.enabled=true"})
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import({JpaConfiguration.class, DeviceConfiguration.class, TrustedDevicePersistenceAdapterIT.TestClock.class})
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class TrustedDevicePersistenceAdapterIT {
    /** The slice has no RestConfiguration, so the clock the adapter stamps audit rows with comes from here. */
    @org.springframework.boot.test.context.TestConfiguration
    static class TestClock {
        @org.springframework.context.annotation.Bean
        java.time.Clock clock() {
            return Clock.fixed(NOW, ZoneOffset.UTC);
        }
    }

    @Container
    static final MySQLContainer<?> MYSQL = new MySQLContainer<>("mysql:8.4");
    private static final CustomerId ALICE = new CustomerId("90359");
    private static final DeviceId PHONE = new DeviceId("dev-1");

    @DynamicPropertySource
    static void settings(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", MYSQL::getJdbcUrl);
        registry.add("spring.datasource.username", MYSQL::getUsername);
        registry.add("spring.datasource.password", MYSQL::getPassword);
        registry.add("auth.device.lookup-hmac-keys-base64.d1", () -> Base64.getEncoder().encodeToString(new byte[32]));
        registry.add("auth.device.encryption-keys-base64.e1", () -> Base64.getEncoder().encodeToString(new byte[32]));
    }

    @Autowired TrustedDeviceRepository devices;
    @Autowired TrustedDeviceRevocationStore revocations;
    @Autowired TrustedDeviceJpaRepository rows;
    @Autowired PrimaryTrustedDeviceJpaRepository primaries;
    @Autowired TrustedDeviceAuditJpaRepository audit;
    @Autowired DeviceIdProtection protection;
    @Autowired JdbcClient jdbc;
    @Autowired EntityManagerFactory entityManagerFactory;
    private static final Instant NOW = Instant.parse("2026-10-25T10:00:00.123Z");
    private final Instant now = NOW;

    @BeforeEach
    void clean() {
        audit.deleteAll();
        primaries.deleteAll();
        rows.deleteAll();
        jdbc.sql("DELETE FROM TRUSTED_DEVICE_REVOKE").update();
        jdbc.sql("DELETE FROM CUSTOMER_AUTHENTICATION").update();
        jdbc.sql("""
                INSERT INTO CUSTOMER_AUTHENTICATION
                    (CUSTOMER_ID, USER_NAME, IDENTITY_ISSUER, IDENTITY_SUBJECT, STATUS, CREATED_AT, UPDATED_AT)
                VALUES ('90359', 'alice', 'issuer', 'alice-subject', 'ACTIVE', UTC_TIMESTAMP(), UTC_TIMESTAMP())
                """).update();
    }

    @Test
    void theInstallationKeyAllowsOnlyOneBindingEvenWhenItsDeadlinePassed() {
        TrustedDevice device = seedTrustedPrimary(PHONE);
        TrustedDevice second = DomainFixtures.trustedDevice(new DeviceInstallation(ALICE, Channel.MOBILE, PHONE),
                DevicePlatform.IOS, "{different-key}", device.expiresAt());
        assertThatThrownBy(() -> rows.saveAndFlush(TrustedDevicePersistenceMapper.toEntity(second, protection)))
                .isInstanceOf(DataIntegrityViolationException.class);

        assertThat(jdbc.sql("""
                SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
                WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'TRUSTED_DEVICE' AND COLUMN_NAME = 'LIVE_SLOT'
                """).query(Long.class).single()).isZero();
        assertThat(devices.findLive(ALICE, Channel.MOBILE, PHONE)).map(TrustedDevice::id).contains(device.id());
    }

    @Test
    void aPrimaryLoginReadsTheDeviceAndUpdatesItsTimestampWithinTheSqlBudget() {
        TrustedDevice device = seedTrustedPrimary(PHONE);
        Instant loggedInAt = now.plusSeconds(60);
        TrustedDeviceService trustedDeviceService = new TrustedDeviceService(devices, DevicePolicy.standard(),
                TrustedDeviceId::random, Clock.fixed(loggedInAt, ZoneOffset.UTC));
        RouteAfterPasswordCommand login = new RouteAfterPasswordCommand(ALICE, Channel.MOBILE, PHONE);
        Statistics statistics = entityManagerFactory.unwrap(SessionFactory.class).getStatistics();
        boolean wasEnabled = statistics.isStatisticsEnabled();
        statistics.setStatisticsEnabled(true);
        statistics.clear();

        DeviceRouting routing;
        long sqlStatements;
        try {
            routing = trustedDeviceService.routeAfterPassword(login, candidate -> candidate.id().equals(device.id()));
            sqlStatements = statistics.getPrepareStatementCount();
        } finally {
            statistics.setStatisticsEnabled(wasEnabled);
        }

        assertThat(routing).isInstanceOf(DeviceRouting.FullSession.class);
        assertThat(sqlStatements).as("one primary lookup and one metadata update").isEqualTo(2);
        assertThat(rows.findById(device.id().value()).orElseThrow().getLastSuccessfulLoginAt()).isEqualTo(loggedInAt);
        assertThat(audit.count()).isZero();
    }

    @Test
    void anExpiredPrimaryNeedsTrustAfterOnlyOneReadAndNoWrite() {
        TrustedDevice device = seedTrustedPrimary(PHONE);
        TrustedDeviceService service = new TrustedDeviceService(devices, DevicePolicy.standard(),
                TrustedDeviceId::random, Clock.fixed(device.expiresAt(), ZoneOffset.UTC));
        RouteAfterPasswordCommand login = new RouteAfterPasswordCommand(ALICE, Channel.MOBILE, PHONE);
        Statistics statistics = entityManagerFactory.unwrap(SessionFactory.class).getStatistics();
        boolean wasEnabled = statistics.isStatisticsEnabled();
        statistics.setStatisticsEnabled(true);
        statistics.clear();
        try {
            assertThat(service.routeAfterPassword(login, candidate -> {
                throw new AssertionError("An expired binding cannot reach proof verification");
            })).isInstanceOf(DeviceRouting.NeedTrust.class);
            assertThat(statistics.getPrepareStatementCount()).isEqualTo(1);
        } finally {
            statistics.setStatisticsEnabled(wasEnabled);
        }
        assertThat(rows.findById(device.id().value())).isPresent();
        assertThat(audit.count()).isZero();
    }

    @Test
    void revokeMovesTheSnapshotAndClearsPrimaryOnceWithoutBlockingANewBinding() {
        TrustedDevice original = seedTrustedPrimary(PHONE);
        DeviceRevocation revoke = revocationOf(original);
        TrustedDeviceEntity before = rows.findById(original.id().value()).orElseThrow();
        Instant loggedInAt = now.plusSeconds(60);
        assertThat(devices.recordLoginIfCurrent(original.id(), original.version(), loggedInAt)).isTrue();
        assertThat(devices.recordLoginIfCurrent(original.id(), original.version(), loggedInAt.plusSeconds(1))).isFalse();
        assertThat(devices.recordLoginIfCurrent(original.id(), original.version() + 1, loggedInAt.minusSeconds(1))).isFalse();

        assertThat(revocations.revoke(revoke)).isEqualTo(RevocationCommit.COMMITTED);
        assertThat(revocations.revoke(revoke)).isEqualTo(RevocationCommit.ALREADY_COMMITTED);
        assertThat(rows.findById(original.id().value())).isEmpty();
        assertThat(devices.findPrimary(ALICE, Channel.MOBILE)).isEmpty();
        assertThat(devices.findLivePrimary(new DeviceInstallation(ALICE, Channel.MOBILE, PHONE))).isEmpty();
        assertThat(devices.recordLoginIfCurrent(original.id(), original.version() + 1, loggedInAt.plusSeconds(1))).isFalse();
        assertThat(jdbc.sql("SELECT CLIENT_DEVICE_ID_CIPHERTEXT FROM TRUSTED_DEVICE_REVOKE").query(byte[].class).single())
                .isEqualTo(before.getClientDeviceIdCiphertext());
        assertThat(jdbc.sql("SELECT STATUS FROM TRUSTED_DEVICE_REVOKE").query(String.class).single())
                .isEqualTo("REVOKED");
        assertThat(jdbc.sql("SELECT VERSION FROM TRUSTED_DEVICE_REVOKE").query(Long.class).single())
                .isEqualTo(original.version() + 1);
        assertThat(audit.findByCorrelationIdOrderByEventSequenceAsc(revoke.correlationId()))
                .extracting(TrustedDeviceAuditEntity::getEventType).containsExactly("DEVICE_REVOKED", "PRIMARY_CHANGED");

        TrustedDevice replacement = DomainFixtures.trustedDevice(new DeviceInstallation(ALICE, Channel.MOBILE, PHONE),
                DevicePlatform.ANDROID, "{new-key}", now.plusSeconds(60));
        rows.saveAndFlush(TrustedDevicePersistenceMapper.toEntity(replacement, protection));
        assertThat(revocations.revoke(revoke)).isEqualTo(RevocationCommit.ALREADY_COMMITTED);
        assertThat(devices.findLive(ALICE, Channel.MOBILE, PHONE)).map(TrustedDevice::id).contains(replacement.id());
    }

    @Test
    void anAuditFailureRollsBackTheSnapshotBindingDeletionAndPrimaryClear() {
        TrustedDevice original = seedTrustedPrimary(PHONE);
        DeviceRevocation revoke = revocationOf(original);
        jdbc.sql("""
                ALTER TABLE TRUSTED_DEVICE_AUDIT ADD CONSTRAINT reject_device_revoke_audit
                CHECK (EVENT_TYPE <> 'DEVICE_REVOKED')
                """).update();
        try {
            assertThatThrownBy(() -> revocations.revoke(revoke)).isInstanceOf(RepositoryUnavailableException.class);
        } finally {
            jdbc.sql("ALTER TABLE TRUSTED_DEVICE_AUDIT DROP CHECK reject_device_revoke_audit").update();
        }

        assertThat(rows.findById(original.id().value())).isPresent();
        assertThat(devices.findPrimary(ALICE, Channel.MOBILE)).contains(original.id());
        assertThat(jdbc.sql("SELECT COUNT(*) FROM TRUSTED_DEVICE_REVOKE").query(Long.class).single()).isZero();
        assertThat(audit.count()).isZero();
    }

    private static DeviceRevocation revocationOf(TrustedDevice original) {
        return new DeviceRevocation(ALICE, Channel.MOBILE, original.id(), original.id(), "CUSTOMER_REQUEST", "revoke-1");
    }

    @Test
    void aRowEncryptedForAnotherOwnerIsNotADevice() {
        seedTrustedPrimary(PHONE);
        jdbc.sql("UPDATE TRUSTED_DEVICE SET CUSTOMER_ID = '77777'").update();

        assertThat(devices.findLive(new CustomerId("77777"), Channel.MOBILE)).isEmpty();
    }

    /** A row an earlier enrollment trusted, and the primary row pointing at it (a login never writes these, slice 13). */
    private TrustedDevice seedTrustedPrimary(DeviceId deviceId) {
        TrustedDevice device = DomainFixtures.trustedDevice(new DeviceInstallation(ALICE, Channel.MOBILE, deviceId),
                DevicePlatform.ANDROID, "{phone-key}", now);
        rows.saveAndFlush(TrustedDevicePersistenceMapper.toEntity(device, protection));
        primaries.saveAndFlush(TrustedDevicePersistenceMapper.toPrimary(device, now));
        return device;
    }
}
