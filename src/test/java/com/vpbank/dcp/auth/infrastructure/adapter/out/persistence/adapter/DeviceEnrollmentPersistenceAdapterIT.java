package com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.adapter;

import static org.assertj.core.api.Assertions.assertThat;

import com.vpbank.dcp.auth.application.port.out.model.TrustConfirmation;
import com.vpbank.dcp.auth.application.port.out.repository.EnrollmentRepository;
import com.vpbank.dcp.auth.application.port.out.repository.TrustedDeviceRepository;
import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.DevicePlatform;
import com.vpbank.dcp.auth.domain.enums.DeviceStatus;
import com.vpbank.dcp.auth.domain.enums.EnrollmentState;
import com.vpbank.dcp.auth.domain.enums.PrimaryMode;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceEnrollment;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.DevicePolicy;
import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import com.vpbank.dcp.auth.domain.model.SessionId;
import com.vpbank.dcp.auth.domain.model.TrustedDevice;
import com.vpbank.dcp.auth.domain.model.TrustedDeviceId;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.entity.TrustedDeviceAuditEntity;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.DeviceEnrollmentJpaRepository;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.PrimaryTrustedDeviceJpaRepository;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.TrustedDeviceAuditJpaRepository;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.TrustedDeviceJpaRepository;
import com.vpbank.dcp.auth.infrastructure.config.DeviceConfiguration;
import com.vpbank.dcp.auth.infrastructure.config.JpaConfiguration;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/** Phase-4 rows on real MySQL: idempotent create, protected device lookup, CAS, and the confirmed-trust transaction. */
@Testcontainers
@DataJpaTest(properties = {"spring.jpa.hibernate.ddl-auto=validate", "spring.flyway.enabled=true", "auth.login.enabled=true"})
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import({JpaConfiguration.class, DeviceConfiguration.class, DeviceEnrollmentPersistenceAdapterIT.TestClock.class})
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class DeviceEnrollmentPersistenceAdapterIT {
    @TestConfiguration
    static class TestClock {
        @Bean
        java.time.Clock clock() {
            return java.time.Clock.systemUTC();
        }
    }

    @Container
    static final MySQLContainer<?> MYSQL = new MySQLContainer<>("mysql:8.4");
    private static final CustomerId ALICE = new CustomerId("90359");
    private static final DeviceId PHONE = new DeviceId("phone-1");
    private static final DeviceId TABLET = new DeviceId("tablet-2");

    @DynamicPropertySource
    static void settings(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", MYSQL::getJdbcUrl);
        registry.add("spring.datasource.username", MYSQL::getUsername);
        registry.add("spring.datasource.password", MYSQL::getPassword);
        registry.add("auth.device.lookup-hmac-keys-base64.d1", () -> Base64.getEncoder().encodeToString(new byte[32]));
        registry.add("auth.device.encryption-keys-base64.e1", () -> Base64.getEncoder().encodeToString(new byte[32]));
    }

    @Autowired EnrollmentRepository enrollments;
    @Autowired TrustedDeviceRepository devices;
    @Autowired DeviceEnrollmentJpaRepository enrollmentRows;
    @Autowired TrustedDeviceJpaRepository deviceRows;
    @Autowired PrimaryTrustedDeviceJpaRepository primaries;
    @Autowired TrustedDeviceAuditJpaRepository audit;
    @Autowired JdbcClient jdbc;
    private final Instant now = Instant.parse("2026-10-25T10:00:00.123Z");

    @BeforeEach
    void clean() {
        audit.deleteAll();
        enrollmentRows.deleteAll();
        primaries.deleteAll();
        deviceRows.deleteAll();
    }

    @Test
    void createIsIdempotentPerRestrictedSessionAndTheRowHoldsOnlyTheDeviceLookup() {
        SessionId session = SessionId.random();
        DeviceEnrollment first = enrollments.create(DeviceEnrollment.start(EnrollmentId.random(), ALICE, Channel.MOBILE, TABLET,
                null, now.plusSeconds(600)), session);
        DeviceEnrollment again = enrollments.create(DeviceEnrollment.start(EnrollmentId.random(), ALICE, Channel.MOBILE, TABLET,
                null, now.plusSeconds(600)), session);

        assertThat(again.id()).isEqualTo(first.id());
        assertThat(enrollmentRows.count()).isEqualTo(1);
        assertThat(jdbc.sql("SELECT HEX(TARGET_CLIENT_DEVICE_ID_LOOKUP) FROM TRUSTED_DEVICE_ENROLLMENT").query(String.class).single())
                .hasSize(64).doesNotContain(java.util.HexFormat.of().withUpperCase().formatHex("tablet-2".getBytes()));
        assertThat(enrollments.find(first.id(), ALICE, TABLET)).isPresent();
        assertThat(enrollments.find(first.id(), ALICE, PHONE)).isEmpty();           // another device cannot borrow it
        assertThat(enrollments.find(first.id(), new CustomerId("77777"), TABLET)).isEmpty();
        // Another session of the same customer may start its own enrollment.
        assertThat(enrollments.create(DeviceEnrollment.start(EnrollmentId.random(), ALICE, Channel.MOBILE, TABLET, null,
                now.plusSeconds(600)), SessionId.random()).id()).isNotEqualTo(first.id());
    }

    @Test
    void stepsAreCompareAndSetOnVersion() {
        DeviceEnrollment created = enrollments.create(DeviceEnrollment.start(EnrollmentId.random(), ALICE, Channel.MOBILE, TABLET,
                null, now.plusSeconds(600)), SessionId.random());
        DeviceEnrollment counted = enrollments.saveIfCurrent(created.countAttempt()).orElseThrow();
        assertThat(counted.verifyAttempts()).isEqualTo(1);
        assertThat(counted.version()).isEqualTo(1);
        assertThat(enrollments.saveIfCurrent(created.countAttempt())).isEmpty(); // stale
        DeviceEnrollment mfa = enrollments.saveIfCurrent(counted.markMfaRequired("mfa-1")).orElseThrow();
        assertThat(mfa.state()).isEqualTo(EnrollmentState.MFA_REQUIRED);
        assertThat(enrollments.find(mfa.id(), ALICE, TABLET).orElseThrow().mfaTransactionId()).isEqualTo("mfa-1");
    }

    @Test
    void confirmedTrustWritesDeviceReplacementPrimaryEnrollmentAndAuditTogether() {
        // Phone is the direct primary; an old tablet row exists (reinstall case).
        devices.trustFirstDevice(TrustedDevice.trustedNow(TrustedDeviceId.random(), ALICE, Channel.MOBILE, PHONE,
                DevicePlatform.ANDROID, null, now, DevicePolicy.standard()), "corr-0");
        TrustedDevice oldTablet = TrustedDevice.trustedNow(TrustedDeviceId.random(), ALICE, Channel.MOBILE, TABLET,
                DevicePlatform.IOS, "{old}", now, DevicePolicy.standard());
        deviceRows.saveAndFlush(com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.mapper.TrustedDevicePersistenceMapper
                .toEntity(oldTablet, protection()));
        DeviceEnrollment created = enrollments.create(DeviceEnrollment.start(EnrollmentId.random(), ALICE, Channel.MOBILE, TABLET,
                oldTablet.id(), now.plusSeconds(600)), SessionId.random());
        DeviceEnrollment counted = enrollments.saveIfCurrent(created.countAttempt()).orElseThrow();
        DeviceEnrollment enrollment = enrollments.saveIfCurrent(counted.markMfaRequired("mfa-1")).orElseThrow();
        TrustedDevice newTablet = TrustedDevice.trustedByEnrollment(TrustedDeviceId.random(), ALICE, Channel.MOBILE, TABLET,
                DevicePlatform.IOS, "{new}", now, DevicePolicy.standard());

        TrustedDevice trusted = devices.trustConfirmed(TrustConfirmation.builder().device(newTablet)
                .replaced(oldTablet.expire()).expiredByCap(List.of()).enrollment(enrollment.complete())
                .primaryMode(PrimaryMode.FACE_CONFIRMED).faceAuthenticated(true)
                .receiptDigest("receipt-sha").build(), "corr-1");

        assertThat(trusted.publicKey()).isEqualTo("{new}");
        assertThat(devices.findLive(ALICE, Channel.MOBILE, TABLET).orElseThrow().id()).isEqualTo(newTablet.id());
        assertThat(deviceRows.findById(oldTablet.id().value()).orElseThrow().getStatus()).isEqualTo(DeviceStatus.EXPIRED);
        assertThat(devices.findLive(ALICE, Channel.MOBILE)).hasSize(2); // phone stays trusted
        assertThat(devices.findPrimary(ALICE, Channel.MOBILE)).contains(newTablet.id());
        var primary = primaries.findAll().getFirst();
        assertThat(primary.getPrimaryMode()).isEqualTo(PrimaryMode.FACE_CONFIRMED);
        assertThat(primary.isFaceAuthenticated()).isTrue();
        assertThat(primary.getPrimaryEnrollmentId()).isEqualTo(enrollment.id().value());
        var row = enrollmentRows.findById(enrollment.id().value()).orElseThrow();
        assertThat(row.getState()).isEqualTo(EnrollmentState.COMPLETED);
        assertThat(row.getConfirmedMfaMethod()).isEqualTo("FACE");
        assertThat(row.getMfaConfirmedAt()).isNotNull();
        assertThat(audit.findByCorrelationIdOrderByEventSequenceAsc("corr-1"))
                .extracting(TrustedDeviceAuditEntity::getEventType)
                .containsExactly("DEVICE_REPLACED", "DEVICE_TRUSTED", "PRIMARY_CHANGED");
        assertThat(audit.findByCorrelationIdOrderByEventSequenceAsc("corr-1").get(1).getMetadata()).contains("receipt-sha");
        assertThat(audit.findByCorrelationIdOrderByEventSequenceAsc("corr-1")).allSatisfy(a ->
                assertThat(a.getEnrollmentId()).isEqualTo(enrollment.id().value()));
        // The direct primary of the phone kept its mode.
        assertThat(jdbc.sql("SELECT COUNT(*) FROM PRIMARY_TRUSTED_DEVICE").query(Long.class).single()).isEqualTo(1L);
    }

    @Test
    void anApprovalIsBoundToItsSessionReadableFromThePrimarySideAndCommitsThePendingRowAsPrimary() {
        // The phone is the direct primary; the watch registered a PENDING row and asked for approval.
        TrustedDevice phone = TrustedDevice.trustedNow(TrustedDeviceId.random(), ALICE, Channel.MOBILE, PHONE,
                DevicePlatform.ANDROID, null, now, DevicePolicy.standard());
        devices.trustFirstDevice(phone, "corr-0");
        DeviceId watchId = new DeviceId("watch-3");
        TrustedDevice watch = TrustedDevice.pending(TrustedDeviceId.random(), ALICE, Channel.MOBILE, watchId,
                DevicePlatform.IOS, "{watch-key}", now, Duration.ofMinutes(10));
        devices.registerPending(watch, "corr-r");
        SessionId watchSession = SessionId.random();
        DeviceEnrollment requested = enrollments.create(DeviceEnrollment.requestApproval(EnrollmentId.random(), ALICE,
                Channel.MOBILE, watchId, watch.id(), now.plusSeconds(600)), watchSession);

        // Bound to the session and the installation that made it.
        assertThat(enrollments.findBySession(ALICE, watchId, watchSession)).map(DeviceEnrollment::id).contains(requested.id());
        assertThat(enrollments.findBySession(ALICE, watchId, SessionId.random())).isEmpty();
        assertThat(enrollments.findBySession(ALICE, PHONE, watchSession)).isEmpty();
        assertThat(jdbc.sql("SELECT HEX(REQUESTER_CLIENT_DEVICE_ID_LOOKUP) FROM TRUSTED_DEVICE_ENROLLMENT").query(String.class).single())
                .hasSize(64);

        // The primary side recovers the requester's device ID from the target row's ciphertext.
        DeviceEnrollment seenByPhone = enrollments.findApproval(requested.id(), ALICE, Channel.MOBILE).orElseThrow();
        assertThat(seenByPhone.deviceId()).isEqualTo(watchId);
        assertThat(seenByPhone.state()).isEqualTo(EnrollmentState.WAITING_APPROVAL);
        assertThat(enrollments.findOpenApprovals(ALICE, Channel.MOBILE)).extracting(DeviceEnrollment::id).containsExactly(requested.id());
        assertThat(enrollments.findApproval(requested.id(), new CustomerId("77777"), Channel.MOBILE)).isEmpty();

        // Approve, authorize (token digest + MFA time), count a claim: every column round-trips.
        DeviceEnrollment approved = enrollments.saveIfCurrent(seenByPhone.approveBy(phone.id(), "mfa-7")).orElseThrow();
        String tokenDigest = Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[]{
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32});
        DeviceEnrollment authorized = enrollments.saveIfCurrent(approved.authorize(tokenDigest, now.plusSeconds(180), "FACE+OTP"))
                .orElseThrow();
        DeviceEnrollment counted = enrollments.saveIfCurrent(authorized.countClaimAttempt()).orElseThrow();
        var row = enrollmentRows.findById(requested.id().value()).orElseThrow();
        assertThat(row.getState()).isEqualTo(EnrollmentState.WAITING_AUTHORIZATION);
        assertThat(row.getActorDeviceId()).isEqualTo(phone.id().value());
        assertThat(row.getMultifactorId()).isEqualTo("mfa-7");
        assertThat(row.getConfirmedMfaMethod()).isEqualTo("FACE+OTP");
        assertThat(row.getMfaConfirmedAt()).isNotNull();
        assertThat(row.getAuthorizationTokenDigest()).hasSize(32).startsWith(new byte[]{1, 2, 3});
        assertThat(row.getAuthorizationExpiresAt()).isEqualTo(now.plusSeconds(180));
        assertThat(row.getAuthorizationAttempts()).isEqualTo(1);
        DeviceEnrollment reread = enrollments.findBySession(ALICE, watchId, watchSession).orElseThrow();
        assertThat(reread.authorizationTokenDigest()).isEqualTo(tokenDigest);
        assertThat(reread.authorizationAttempts()).isEqualTo(1);
        assertThat(reread.verifyAttempts()).isZero();
        assertThat(reread.mfaMethod()).isEqualTo("FACE+OTP");

        // The claim: the PENDING row becomes trusted and primary in one transaction with the enrollment and audit.
        DeviceEnrollment consumed = counted.consumeAuthorization(now.plusSeconds(60));
        TrustedDevice approvedWatch = devices.findLive(ALICE, Channel.MOBILE, watchId).orElseThrow()
                .trustByApproval(now.plusSeconds(60), DevicePolicy.standard());
        TrustedDevice trusted = devices.trustConfirmed(TrustConfirmation.builder().device(approvedWatch).replaced(null)
                .expiredByCap(List.of()).enrollment(consumed).primaryMode(PrimaryMode.OLD_DEVICE_APPROVAL)
                .faceAuthenticated(false).actorDeviceId(phone.id()).build(), "corr-c");

        assertThat(trusted.id()).isEqualTo(watch.id());
        assertThat(deviceRows.count()).isEqualTo(2); // the pending row moved, no new row
        assertThat(deviceRows.findById(watch.id().value()).orElseThrow().getStatus()).isEqualTo(DeviceStatus.ACTIVE);
        assertThat(devices.findLive(ALICE, Channel.MOBILE, watchId).orElseThrow().isTrusted(now.plusSeconds(60))).isTrue();
        assertThat(devices.findLive(ALICE, Channel.MOBILE, PHONE).orElseThrow().isTrusted(now.plusSeconds(60))).isTrue();
        assertThat(devices.findPrimary(ALICE, Channel.MOBILE)).contains(watch.id());
        var primary = primaries.findAll().getFirst();
        assertThat(primary.getPrimaryMode()).isEqualTo(PrimaryMode.OLD_DEVICE_APPROVAL);
        assertThat(primary.isFaceAuthenticated()).isFalse();
        assertThat(primary.getPrimaryEnrollmentId()).isEqualTo(requested.id().value());
        var completedRow = enrollmentRows.findById(requested.id().value()).orElseThrow();
        assertThat(completedRow.getState()).isEqualTo(EnrollmentState.COMPLETED);
        assertThat(completedRow.getAuthorizationConsumedAt()).isEqualTo(now.plusSeconds(60));
        assertThat(completedRow.getAuthorizedSessionRefDigest()).isEqualTo(completedRow.getCreationIdempotencyDigest());
        assertThat(enrollments.findOpenApprovals(ALICE, Channel.MOBILE)).isEmpty();
        List<TrustedDeviceAuditEntity> events = audit.findByCorrelationIdOrderByEventSequenceAsc("corr-c");
        assertThat(events).extracting(TrustedDeviceAuditEntity::getEventType).containsExactly("DEVICE_TRUSTED", "PRIMARY_CHANGED");
        assertThat(events).extracting(TrustedDeviceAuditEntity::getReasonCode).containsOnly("OLD_DEVICE_APPROVAL");
        assertThat(events).extracting(TrustedDeviceAuditEntity::getActorDeviceId).containsOnly(phone.id().value());
        assertThat(events.getFirst().getMetadata()).contains(phone.id().value().toString());
    }

    @Autowired com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.common.DeviceIdProtection protectionBean;

    private com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.common.DeviceIdProtection protection() {
        return protectionBean;
    }
}
