package com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.adapter;

import static org.assertj.core.api.Assertions.assertThat;

import com.vpbank.dcp.auth.application.port.out.repository.TrustedDeviceRepository.TrustFirstResult;
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

/** Phase-3 tables on real MySQL: protected device ID, live-slot unique key, the first-device transaction, audit sequence, CAS. */
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
    void trustsTheFirstDeviceWithPrimaryAndTwoAuditEventsInOneTransaction() {
        TrustedDevice phone = TrustedDevice.trustedNow(TrustedDeviceId.random(), ALICE, Channel.MOBILE, PHONE,
                DevicePlatform.ANDROID, "{\"kty\":\"EC\"}", now, DevicePolicy.standard());

        TrustFirstResult result = devices.trustFirstDevice(phone, "corr-1");

        assertThat(result).isInstanceOf(TrustFirstResult.Trusted.class);
        TrustedDevice stored = devices.findLive(ALICE, Channel.MOBILE, PHONE).orElseThrow();
        assertThat(stored.deviceId()).isEqualTo(PHONE);
        assertThat(stored.expiresAt()).isEqualTo(now.plus(180, ChronoUnit.DAYS));
        assertThat(stored.publicKey()).isEqualTo("{\"kty\":\"EC\"}");
        assertThat(devices.findPrimary(ALICE, Channel.MOBILE)).contains(phone.id());
        assertThat(audit.findByCorrelationIdOrderByEventSequenceAsc("corr-1"))
                .extracting(TrustedDeviceAuditEntity::getEventType).containsExactly("DEVICE_TRUSTED", "PRIMARY_ASSIGNED");
        // The device ID is not in clear anywhere in the row.
        assertThat(jdbc.sql("SELECT HEX(CLIENT_DEVICE_ID_CIPHERTEXT) FROM TRUSTED_DEVICE").query(String.class).single())
                .doesNotContain(java.util.HexFormat.of().withUpperCase().formatHex("dev-1".getBytes()));
        assertThat(jdbc.sql("SELECT LIVE_SLOT FROM TRUSTED_DEVICE").query(Integer.class).single()).isEqualTo(1);
    }

    @Test
    void aSecondFirstDeviceForTheSameCustomerIsRefusedAndLeavesNothingBehind() {
        devices.trustFirstDevice(TrustedDevice.trustedNow(TrustedDeviceId.random(), ALICE, Channel.MOBILE, PHONE,
                DevicePlatform.ANDROID, null, now, DevicePolicy.standard()), "corr-1");

        TrustFirstResult again = devices.trustFirstDevice(TrustedDevice.trustedNow(TrustedDeviceId.random(), ALICE,
                Channel.MOBILE, new DeviceId("dev-2"), DevicePlatform.IOS, null, now, DevicePolicy.standard()), "corr-2");

        assertThat(again).isInstanceOf(TrustFirstResult.AlreadyHasDevice.class);
        assertThat(rows.count()).isEqualTo(1);
        assertThat(audit.findByCorrelationIdOrderByEventSequenceAsc("corr-2")).isEmpty();
        // Another customer on the same installation is independent.
        assertThat(devices.trustFirstDevice(TrustedDevice.trustedNow(TrustedDeviceId.random(), new CustomerId("77777"),
                Channel.MOBILE, PHONE, DevicePlatform.ANDROID, null, now, DevicePolicy.standard()), "corr-3"))
                .isInstanceOf(TrustFirstResult.Trusted.class);
    }

    @Test
    void savesAreCompareAndSetAndExpiryFreesTheLiveSlot() {
        devices.trustFirstDevice(TrustedDevice.trustedNow(TrustedDeviceId.random(), ALICE, Channel.MOBILE, PHONE,
                DevicePlatform.ANDROID, null, now, DevicePolicy.standard()), "corr-1");
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
        // The slot is free again: the installation can be registered anew.
        assertThat(devices.trustFirstDevice(TrustedDevice.trustedNow(TrustedDeviceId.random(), ALICE, Channel.MOBILE, PHONE,
                DevicePlatform.ANDROID, null, now, DevicePolicy.standard()), "corr-5"))
                .isInstanceOf(TrustFirstResult.AlreadyHasDevice.class); // …but the primary row still exists (phase 7 clears it)
    }

    @Test
    void aPendingRowIsRegisteredOnceWithItsEventAndCountsAsWaiting() {
        TrustedDevice watch = TrustedDevice.pending(TrustedDeviceId.random(), ALICE, Channel.MOBILE, new DeviceId("watch-3"),
                DevicePlatform.IOS, "{watch-key}", now, Duration.ofMinutes(10));

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
        TrustedDevice again = TrustedDevice.pending(TrustedDeviceId.random(), ALICE, Channel.MOBILE, new DeviceId("watch-3"),
                DevicePlatform.IOS, "{other-key}", now, Duration.ofMinutes(10));
        assertThat(devices.registerPending(again, "corr-r2"))
                .isInstanceOf(TrustedDeviceRepository.RegisterPendingResult.InstallationAlreadyLive.class);
        assertThat(rows.count()).isEqualTo(1);
        assertThat(audit.findByCorrelationIdOrderByEventSequenceAsc("corr-r2")).isEmpty();
        assertThat(devices.countPending(ALICE, Channel.MOBILE)).isEqualTo(1);
    }

    @Test
    void aRowEncryptedForAnotherOwnerIsNotADevice() {
        devices.trustFirstDevice(TrustedDevice.trustedNow(TrustedDeviceId.random(), ALICE, Channel.MOBILE, PHONE,
                DevicePlatform.ANDROID, null, now, DevicePolicy.standard()), "corr-1");
        jdbc.sql("UPDATE TRUSTED_DEVICE SET CUSTOMER_ID = '77777'").update();

        assertThat(devices.findLive(new CustomerId("77777"), Channel.MOBILE)).isEmpty();
    }
}
