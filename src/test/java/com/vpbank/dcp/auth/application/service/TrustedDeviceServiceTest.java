package com.vpbank.dcp.auth.application.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.vpbank.dcp.auth.application.result.DeviceSummary;
import com.vpbank.dcp.auth.application.service.TrustedDeviceService.DevicePossession;
import com.vpbank.dcp.auth.application.service.TrustedDeviceService.DeviceRouting;
import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.DevicePlatform;
import com.vpbank.dcp.auth.domain.enums.DeviceStatus;
import com.vpbank.dcp.auth.domain.enums.EnrollmentState;
import com.vpbank.dcp.auth.domain.enums.TrustLevel;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.DevicePolicy;
import com.vpbank.dcp.auth.domain.model.TrustedDevice;
import com.vpbank.dcp.auth.domain.model.TrustedDeviceId;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.Test;

class TrustedDeviceServiceTest {
    private static final Instant NOW = Instant.parse("2026-10-25T10:00:00Z");
    private static final CustomerId ALICE = new CustomerId("90359");
    private static final DeviceId PHONE = new DeviceId("dev-1");
    private static final DeviceId TABLET = new DeviceId("dev-2");
    /** The login holds the key of whatever row it is asked about / holds none. */
    private static final DevicePossession ANY_KEY = device -> true;
    private static final DevicePossession NO_KEY = device -> false;

    private final InMemoryTrustedDeviceRepository devices = new InMemoryTrustedDeviceRepository();
    private final TrustedDeviceService service = new TrustedDeviceService(devices, DevicePolicy.standard(),
            TrustedDeviceId::random, Clock.fixed(NOW, ZoneOffset.UTC));

    /** A login never trusts: a new device, and a customer with no device at all, wait for the trust flow. */
    @Test
    void aNewDeviceNeedsTrustAndIsNeverRegisteredByALogin() {
        assertThat(service.routeAfterPassword(ALICE, Channel.MOBILE, PHONE, ANY_KEY, "corr-1"))
                .isInstanceOf(DeviceRouting.NeedTrust.class);
        assertThat(devices.rows).isEmpty();
        assertThat(devices.findPrimary(ALICE, Channel.MOBILE)).isEmpty();

        seedTrustedPrimary(PHONE, DevicePlatform.ANDROID);
        assertThat(service.routeAfterPassword(ALICE, Channel.MOBILE, TABLET, ANY_KEY, "corr-2"))
                .isInstanceOf(DeviceRouting.NeedTrust.class);
        assertThat(devices.rows).hasSize(1);
    }

    @Test
    void thePrimaryDeviceThatProvesItsKeyGetsAFullSessionAndItsLastLoginIsRecorded() {
        TrustedDevice phone = seedTrustedPrimary(PHONE, DevicePlatform.ANDROID);
        TrustedDeviceService later = new TrustedDeviceService(devices, DevicePolicy.standard(), TrustedDeviceId::random,
                Clock.fixed(NOW.plusSeconds(600), ZoneOffset.UTC));

        assertThat(later.routeAfterPassword(ALICE, Channel.MOBILE, PHONE, device -> device.id().equals(phone.id()), "corr-2"))
                .isInstanceOf(DeviceRouting.FullSession.class);
        assertThat(devices.only().lastLoginAt()).isEqualTo(NOW.plusSeconds(600));
        assertThat(devices.only().version()).isEqualTo(1);
    }

    /** Slice 13: the primary device that cannot prove its key (reinstall, copied ID) is routed to the trust flow. */
    @Test
    void thePrimaryDeviceThatCannotProveItsKeyNeedsTrustAndNothingIsRecorded() {
        seedTrustedPrimary(PHONE, DevicePlatform.ANDROID);

        assertThat(service.routeAfterPassword(ALICE, Channel.MOBILE, PHONE, NO_KEY, "corr-2"))
                .isInstanceOf(DeviceRouting.NeedTrust.class);
        assertThat(devices.only().lastLoginAt()).isEqualTo(NOW);
        assertThat(devices.only().version()).isZero();
    }

    @Test
    void aTrustedButNotPrimaryOrExpiredDeviceNeedsTrustBeforeTheKeyIsEvenAsked() {
        TrustedDevice phone = seedTrustedPrimary(PHONE, DevicePlatform.ANDROID);
        TrustedDevice tablet = TrustedDevice.trustedNow(TrustedDeviceId.random(), ALICE, Channel.MOBILE, TABLET,
                DevicePlatform.IOS, null, NOW, DevicePolicy.standard());
        devices.rows.put(tablet.id(), tablet); // trusted by a later flow, but the phone stays primary
        List<TrustedDevice> asked = new java.util.ArrayList<>();
        DevicePossession recording = device -> asked.add(device);

        assertThat(service.routeAfterPassword(ALICE, Channel.MOBILE, TABLET, recording, "corr-2"))
                .isInstanceOf(DeviceRouting.NeedTrust.class);

        TrustedDeviceService muchLater = new TrustedDeviceService(devices, DevicePolicy.standard(), TrustedDeviceId::random,
                Clock.fixed(NOW.plus(Duration.ofDays(181)), ZoneOffset.UTC));
        assertThat(muchLater.routeAfterPassword(ALICE, Channel.MOBILE, PHONE, recording, "corr-3"))
                .isInstanceOf(DeviceRouting.NeedTrust.class);
        assertThat(asked).isEmpty();
        assertThat(devices.rows.get(phone.id()).status()).isEqualTo(DeviceStatus.ACTIVE); // expiry is judged, not written here
    }

    @Test
    void webHasNoDeviceTrust() {
        assertThat(service.routeAfterPassword(ALICE, Channel.WEB, null, NO_KEY, "corr-1"))
                .isInstanceOf(DeviceRouting.FullSession.class);
        assertThat(devices.rows).isEmpty();
    }

    @Test
    void theCapExpiresTheOldestDevicesByLastLogin() {
        List<TrustedDevice> live = new java.util.ArrayList<>();
        for (int i = 0; i < 5; i++) {
            TrustedDevice d = TrustedDevice.trustedNow(TrustedDeviceId.random(), ALICE, Channel.MOBILE,
                    new DeviceId("d" + i), DevicePlatform.ANDROID, null, NOW.minus(Duration.ofDays(i)), DevicePolicy.standard());
            devices.rows.put(d.id(), d);
            live.add(d);
        }
        List<TrustedDevice> expired = service.expireBeyondCap(live, "corr-cap");
        assertThat(expired).extracting(d -> d.deviceId().value()).containsExactly("d4");
        assertThat(devices.rows.get(expired.getFirst().id()).status()).isEqualTo(DeviceStatus.EXPIRED);
        assertThat(service.expireBeyondCap(live.subList(0, 3), "corr-cap")).isEmpty();
    }

    @Test
    void confirmTrustReplacesTheSameInstallationEnforcesTheCapAndMakesTheDevicePrimary() {
        for (int i = 0; i < 5; i++) {
            TrustedDevice d = TrustedDevice.trustedNow(TrustedDeviceId.random(), ALICE, Channel.MOBILE, new DeviceId("d" + i),
                    DevicePlatform.ANDROID, null, NOW.minus(Duration.ofDays(i)), DevicePolicy.standard());
            devices.rows.put(d.id(), d);
        }
        TrustedDevice oldTablet = TrustedDevice.trustedNow(TrustedDeviceId.random(), ALICE, Channel.MOBILE, TABLET,
                DevicePlatform.IOS, "{old}", NOW.minus(Duration.ofDays(9)), DevicePolicy.standard());
        devices.rows.put(oldTablet.id(), oldTablet);
        com.vpbank.dcp.auth.domain.model.SessionId restrictedSession = com.vpbank.dcp.auth.domain.model.SessionId.random();
        com.vpbank.dcp.auth.domain.model.AdmittedSession tabletSession = new com.vpbank.dcp.auth.domain.model.AdmittedSession(
                restrictedSession, ALICE, Channel.MOBILE, TABLET, com.vpbank.dcp.auth.domain.enums.SessionStatus.NEED_TRUSTED_DEVICE);
        com.vpbank.dcp.auth.domain.model.DeviceEnrollment enrollment = com.vpbank.dcp.auth.domain.model.DeviceEnrollment
                .fromTransaction(com.vpbank.dcp.auth.domain.model.EnrollmentTransaction.keyExchange(
                        com.vpbank.dcp.auth.domain.model.EnrollmentId.random(), tabletSession, oldTablet.id(), "{new}",
                        DevicePlatform.IOS, "{srv-pub}", "{srv-priv}", "digest")
                        .markMfaRequired("mfa-1"), NOW.plusSeconds(600));

        TrustedDevice trusted = service.confirmTrust(enrollment, restrictedSession, DevicePlatform.IOS, "{new}", "receipt", "corr-c");

        assertThat(trusted.publicKey()).isEqualTo("{new}");
        assertThat(devices.rows.get(oldTablet.id()).status()).isEqualTo(DeviceStatus.EXPIRED); // replaced, not counted as a peer
        assertThat(devices.rows.values().stream().filter(d -> d.status().live()).count()).isEqualTo(5); // 4 others + the tablet
        assertThat(devices.rows.values().stream().filter(d -> d.deviceId().value().equals("d4")).findFirst().orElseThrow().status())
                .isEqualTo(DeviceStatus.EXPIRED); // the oldest by last login left for the cap
        assertThat(devices.findPrimary(ALICE, Channel.MOBILE)).contains(trusted.id());
        assertThat(devices.confirmations.getFirst().enrollment().state())
                .isEqualTo(EnrollmentState.COMPLETED);
        // The row is written for the first time by this commit, bound to the restricted session (slice 11).
        assertThat(devices.confirmations.getFirst().creationSessionId()).isEqualTo(restrictedSession);
        assertThat(service.knownDevice(ALICE, Channel.MOBILE, TABLET)).hasValueSatisfying(k ->
                assertThat(k.publicKey()).isEqualTo("{new}"));
        assertThat(service.knownDevice(ALICE, Channel.MOBILE, new DeviceId("nobody"))).isEmpty();
    }

    @Test
    void theDeviceListMarksThePrimary() {
        seedTrustedPrimary(PHONE, DevicePlatform.ANDROID);
        List<DeviceSummary> list = service.listDevices(ALICE, Channel.MOBILE);
        assertThat(list).hasSize(1);
        assertThat(list.getFirst().primary()).isTrue();
        assertThat(list.getFirst().deviceId()).isEqualTo(PHONE);
        assertThat(service.listDevices(new CustomerId("77777"), Channel.MOBILE)).isEmpty();
    }

    /** A row trusted by an earlier enrollment, and the customer's primary on the channel. */
    private TrustedDevice seedTrustedPrimary(DeviceId deviceId, DevicePlatform platform) {
        TrustedDevice device = TrustedDevice.trustedNow(TrustedDeviceId.random(), ALICE, Channel.MOBILE, deviceId, platform,
                "{\"alg\":\"ML-DSA-65\",\"kty\":\"AKP\",\"pub\":\"" + deviceId.value() + "\"}", NOW, DevicePolicy.standard());
        devices.rows.put(device.id(), device);
        devices.primaries.put(new InMemoryTrustedDeviceRepository.Key(ALICE, Channel.MOBILE), device.id());
        return device;
    }
}
