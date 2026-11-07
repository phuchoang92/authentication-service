package com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.adapter;

import com.vpbank.dcp.auth.domain.model.DeviceInstallation;
import com.vpbank.dcp.auth.domain.model.DomainFixtures;
import com.vpbank.dcp.auth.domain.model.NewDevice;
import static org.assertj.core.api.Assertions.assertThat;

import com.vpbank.dcp.auth.application.port.out.repository.TrustedDeviceRepository;
import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.DevicePlatform;
import com.vpbank.dcp.auth.domain.enums.DeviceStatus;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.DevicePolicy;
import com.vpbank.dcp.auth.domain.model.TrustedDevice;
import com.vpbank.dcp.auth.domain.model.TrustedDeviceId;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.common.DeviceIdProtection;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.entity.TrustedDeviceAuditEntity;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.PrimaryTrustedDeviceJpaRepository;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.TrustedDeviceAuditJpaRepository;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.mapper.TrustedDevicePersistenceMapper;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.TrustedDeviceJpaRepository;
import com.vpbank.dcp.auth.infrastructure.config.DeviceConfiguration;
import com.vpbank.dcp.auth.infrastructure.config.JpaConfiguration;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/** Phase-3 tables on real MySQL: protected device ID, live-slot unique key, audit sequence, CAS. */
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
            return java.time.Clock.systemUTC();
        }
    }

    @Container
    static final MySQLContainer<?> MYSQL = new MySQLContainer<>("mysql:8.4");
    private static final CustomerId ALICE = new CustomerId("90359");
    private static final DeviceId PHONE = new DeviceId("dev-1");
    private static final DeviceInstallation ALICE_WATCH =
            new DeviceInstallation(ALICE, Channel.MOBILE, new DeviceId("watch-3"));

    @DynamicPropertySource
    static void settings(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", MYSQL::getJdbcUrl);
        registry.add("spring.datasource.username", MYSQL::getUsername);
        registry.add("spring.datasource.password", MYSQL::getPassword);
        registry.add("auth.device.lookup-hmac-keys-base64.d1", () -> Base64.getEncoder().encodeToString(new byte[32]));
        registry.add("auth.device.encryption-keys-base64.e1", () -> Base64.getEncoder().encodeToString(new byte[32]));
    }

    @Autowired TrustedDeviceRepository devices;
    @Autowired TrustedDeviceJpaRepository rows;
    @Autowired PrimaryTrustedDeviceJpaRepository primaries;
    @Autowired TrustedDeviceAuditJpaRepository audit;
    @Autowired DeviceIdProtection protection;
    @Autowired JdbcClient jdbc;
    private final Instant now = Instant.parse("2026-10-25T10:00:00.123Z");

    @BeforeEach
    void clean() {
        audit.deleteAll();
        primaries.deleteAll();
        rows.deleteAll();
    }

    @Test
    void savesAreCompareAndSetAndExpiryFreesTheLiveSlot() {
        seedTrustedPrimary(PHONE);
        TrustedDevice phone = devices.findLive(ALICE, Channel.MOBILE, PHONE).orElseThrow();

        TrustedDevice afterLogin = devices.saveIfCurrent(phone.recordLogin(now.plusSeconds(60)), "corr-2").orElseThrow();
        assertThat(afterLogin.version()).isEqualTo(1);
        assertThat(afterLogin.lastLoginAt()).isEqualTo(now.plusSeconds(60));
        assertThat(devices.saveIfCurrent(phone.recordLogin(now.plusSeconds(90)), "corr-3")).isEmpty(); // stale

        assertThat(devices.saveIfCurrent(afterLogin.expire(), "corr-4")).isPresent();
        assertThat(devices.findLive(ALICE, Channel.MOBILE, PHONE)).isEmpty();
        assertThat(devices.findLive(ALICE, Channel.MOBILE)).isEmpty();
        assertThat(audit.findByCorrelationIdOrderByEventSequenceAsc("corr-4"))
                .extracting(TrustedDeviceAuditEntity::getEventType).containsExactly("DEVICE_EXPIRED");
        assertThat(jdbc.sql("SELECT LIVE_SLOT FROM TRUSTED_DEVICE").query(Integer.class).optional()).isEmpty();
    }

    @Test
    void aPendingRowIsRegisteredOnceWithItsEventAndCountsAsWaiting() {
        NewDevice watchRow = DomainFixtures.newDevice(ALICE_WATCH, DevicePlatform.IOS, "{watch-key}", now);
        TrustedDevice watch = TrustedDevice.pending(watchRow, Duration.ofMinutes(10));

        TrustedDeviceRepository.RegisterPendingResult registered = devices.registerPending(watch, "corr-r1");

        assertThat(registered).isInstanceOf(TrustedDeviceRepository.RegisterPendingResult.Registered.class);
        TrustedDevice stored = devices.findLive(ALICE, Channel.MOBILE, new DeviceId("watch-3")).orElseThrow();
        assertThat(stored.isPending()).isTrue();
        assertThat(stored.isTrusted(now)).isFalse();
        assertThat(stored.publicKey()).isEqualTo("{watch-key}");
        assertThat(stored.expiresAt()).isEqualTo(now.plus(Duration.ofMinutes(10)));
        assertThat(devices.countPending(ALICE, Channel.MOBILE)).isEqualTo(1);
        assertThat(audit.findByCorrelationIdOrderByEventSequenceAsc("corr-r1"))
                .extracting(TrustedDeviceAuditEntity::getEventType, TrustedDeviceAuditEntity::getReasonCode)
                .containsExactly(org.assertj.core.groups.Tuple.tuple("DEVICE_REGISTERED", "APPROVAL_REQUESTED"));

        // A second login of the same installation loses the live-slot race and leaves nothing behind.
        NewDevice againRow = DomainFixtures.newDevice(ALICE_WATCH, DevicePlatform.IOS, "{other-key}", now);
        TrustedDevice again = TrustedDevice.pending(againRow, Duration.ofMinutes(10));
        assertThat(devices.registerPending(again, "corr-r2"))
                .isInstanceOf(TrustedDeviceRepository.RegisterPendingResult.InstallationAlreadyLive.class);
        assertThat(rows.count()).isEqualTo(1);
        assertThat(audit.findByCorrelationIdOrderByEventSequenceAsc("corr-r2")).isEmpty();
        assertThat(devices.countPending(ALICE, Channel.MOBILE)).isEqualTo(1);
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
                DevicePlatform.ANDROID, null, now);
        rows.saveAndFlush(TrustedDevicePersistenceMapper.toEntity(device, protection));
        primaries.saveAndFlush(TrustedDevicePersistenceMapper.toPrimary(device, now));
        return device;
    }
}
