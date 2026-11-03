package com.vpbank.dcp.auth.application.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.vpbank.dcp.auth.application.result.DeviceSummary;
import com.vpbank.dcp.auth.application.service.TrustedDeviceService.DeviceRouting;
import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.DevicePlatform;
import com.vpbank.dcp.auth.domain.enums.DeviceStatus;
import com.vpbank.dcp.auth.domain.enums.EnrollmentState;
import com.vpbank.dcp.auth.domain.enums.TrustLevel;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.DeviceKeyClaim;
import com.vpbank.dcp.auth.domain.model.DevicePolicy;
import com.vpbank.dcp.auth.domain.model.DeviceSigningKey;
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
    private static final DeviceKeyClaim NO_KEY = new DeviceKeyClaim.None();
    private static final DeviceSigningKey PHONE_KEY = new DeviceSigningKey(
            "{\"alg\":\"ML-DSA-65\",\"kty\":\"AKP\",\"pub\":\"phone\"}", "a".repeat(43));
    private static final DeviceSigningKey NEW_PHONE_KEY = new DeviceSigningKey(
            "{\"alg\":\"ML-DSA-65\",\"kty\":\"AKP\",\"pub\":\"phone2\"}", "b".repeat(43));

    private final InMemoryTrustedDeviceRepository devices = new InMemoryTrustedDeviceRepository();
    private final TrustedDeviceService service = new TrustedDeviceService(devices, DevicePolicy.standard(),
            TrustedDeviceId::random, Clock.fixed(NOW, ZoneOffset.UTC));

    @Test
    void theFirstDeviceIsTrustedAndMadePrimaryDirectlyWithAnAuditTrail() {
        DeviceRouting routing = service.routeAfterPassword(ALICE, Channel.MOBILE, PHONE, DevicePlatform.ANDROID,
                new DeviceKeyClaim.Unproven("{\"kty\":\"EC\"}"), "corr-1");

        assertThat(routing).isInstanceOf(DeviceRouting.FullSession.class);
        TrustedDevice device = devices.only();
        assertThat(device.deviceId()).isEqualTo(PHONE);
        assertThat(device.status()).isEqualTo(DeviceStatus.ACTIVE);
        assertThat(device.trustLevel()).isEqualTo(TrustLevel.TRUSTED);
        assertThat(device.publicKey()).isEqualTo("{\"kty\":\"EC\"}");
        assertThat(device.expiresAt()).isEqualTo(NOW.plus(Duration.ofDays(180)));
        assertThat(devices.findPrimary(ALICE, Channel.MOBILE)).contains(device.id());
        assertThat(devices.audit).containsExactly("corr-1:0:DEVICE_TRUSTED", "corr-1:1:PRIMARY_ASSIGNED");
    }

    @Test
    void aSecondDeviceNeedsTrustAndIsNotRegisteredByTheDirectPath() {
        service.routeAfterPassword(ALICE, Channel.MOBILE, PHONE, DevicePlatform.ANDROID, NO_KEY, "corr-1");

        assertThat(service.routeAfterPassword(ALICE, Channel.MOBILE, TABLET, DevicePlatform.IOS, NO_KEY, "corr-2"))
                .isInstanceOf(DeviceRouting.NeedTrust.class);
        assertThat(devices.rows).hasSize(1);
        assertThat(devices.findPrimary(ALICE, Channel.MOBILE)).contains(devices.only().id());
    }

    @Test
    void thePrimaryDeviceGetsAFullSessionAndItsLastLoginIsRecorded() {
        service.routeAfterPassword(ALICE, Channel.MOBILE, PHONE, DevicePlatform.ANDROID, NO_KEY, "corr-1");
        TrustedDeviceService later = new TrustedDeviceService(devices, DevicePolicy.standard(), TrustedDeviceId::random,
                Clock.fixed(NOW.plusSeconds(600), ZoneOffset.UTC));

        assertThat(later.routeAfterPassword(ALICE, Channel.MOBILE, PHONE, DevicePlatform.ANDROID, NO_KEY, "corr-2"))
                .isInstanceOf(DeviceRouting.FullSession.class);
        assertThat(devices.only().lastLoginAt()).isEqualTo(NOW.plusSeconds(600));
        assertThat(devices.only().version()).isEqualTo(1);
        assertThat(devices.audit).hasSize(2);
    }

    @Test
    void aTrustedButNotPrimaryOrExpiredDeviceNeedsTrust() {
        service.routeAfterPassword(ALICE, Channel.MOBILE, PHONE, DevicePlatform.ANDROID, NO_KEY, "corr-1");
        TrustedDevice phone = devices.only();
        TrustedDevice tablet = TrustedDevice.trustedNow(TrustedDeviceId.random(), ALICE, Channel.MOBILE, TABLET,
                DevicePlatform.IOS, null, NOW, DevicePolicy.standard());
        devices.rows.put(tablet.id(), tablet); // trusted by a later flow, but the phone stays primary

        assertThat(service.routeAfterPassword(ALICE, Channel.MOBILE, TABLET, DevicePlatform.IOS, NO_KEY, "corr-2"))
                .isInstanceOf(DeviceRouting.NeedTrust.class);

        TrustedDeviceService muchLater = new TrustedDeviceService(devices, DevicePolicy.standard(), TrustedDeviceId::random,
                Clock.fixed(NOW.plus(Duration.ofDays(181)), ZoneOffset.UTC));
        assertThat(muchLater.routeAfterPassword(ALICE, Channel.MOBILE, PHONE, DevicePlatform.ANDROID, NO_KEY, "corr-3"))
                .isInstanceOf(DeviceRouting.NeedTrust.class);
        assertThat(devices.rows.get(phone.id()).status()).isEqualTo(DeviceStatus.ACTIVE); // expiry is judged, not written here
    }

    /** Slice 13: a proven key is what the trusted row holds; another proven key means the installation must trust again. */
    @Test
    void aProvenKeyIsStoredForTheFirstDeviceAndTheProvenKeyMustMatchTheRowAfterwards() {
        DeviceRouting first = service.routeAfterPassword(ALICE, Channel.MOBILE, PHONE, DevicePlatform.ANDROID,
                new DeviceKeyClaim.Proven(PHONE_KEY), "corr-1");
        assertThat(first).isInstanceOf(DeviceRouting.FullSession.class);
        assertThat(devices.only().publicKey()).isEqualTo(PHONE_KEY.publicJwk());
        assertThat(devices.only().hasKey(PHONE_KEY)).isTrue();

        assertThat(service.routeAfterPassword(ALICE, Channel.MOBILE, PHONE, DevicePlatform.ANDROID,
                new DeviceKeyClaim.Proven(PHONE_KEY), "corr-2")).isInstanceOf(DeviceRouting.FullSession.class);
        assertThat(service.routeAfterPassword(ALICE, Channel.MOBILE, PHONE, DevicePlatform.ANDROID,
                new DeviceKeyClaim.Proven(NEW_PHONE_KEY), "corr-3")).isInstanceOf(DeviceRouting.NeedTrust.class);
        assertThat(devices.rows).hasSize(1); // the reinstalled app is not re-trusted by the direct path
        assertThat(devices.findPrimary(ALICE, Channel.MOBILE)).contains(devices.only().id());
    }

    /** A row trusted before the proof existed holds no key, so a proven key never matches it: trust again. */
    @Test
    void aRowWithoutAKeyNeverMatchesAProvenKeyButStillServesAnUnprovenLogin() {
        service.routeAfterPassword(ALICE, Channel.MOBILE, PHONE, DevicePlatform.ANDROID, NO_KEY, "corr-1");
        assertThat(devices.only().publicKey()).isNull();

        assertThat(service.routeAfterPassword(ALICE, Channel.MOBILE, PHONE, DevicePlatform.ANDROID,
                new DeviceKeyClaim.Proven(PHONE_KEY), "corr-2")).isInstanceOf(DeviceRouting.NeedTrust.class);
        assertThat(service.routeAfterPassword(ALICE, Channel.MOBILE, PHONE, DevicePlatform.ANDROID,
                new DeviceKeyClaim.Unproven(PHONE_KEY.publicJwk()), "corr-3")).isInstanceOf(DeviceRouting.FullSession.class);
    }

    @Test
    void webHasNoDeviceTrustAndARaceOnTheFirstDeviceFallsBackToNeedTrust() {
        assertThat(service.routeAfterPassword(ALICE, Channel.WEB, null, null, NO_KEY, "corr-1"))
                .isInstanceOf(DeviceRouting.FullSession.class);
        assertThat(devices.rows).isEmpty();

        devices.primaries.put(new InMemoryTrustedDeviceRepository.Key(ALICE, Channel.MOBILE), TrustedDeviceId.random());
        assertThat(service.routeAfterPassword(ALICE, Channel.MOBILE, PHONE, DevicePlatform.ANDROID, NO_KEY, "corr-2"))
                .isInstanceOf(DeviceRouting.NeedTrust.class);
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
                        DevicePlatform.IOS, "{srv-pub}", "{srv-priv}", "digest", NOW.plusSeconds(600))
                        .markMfaRequired("mfa-1"));

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
        service.routeAfterPassword(ALICE, Channel.MOBILE, PHONE, DevicePlatform.ANDROID, NO_KEY, "corr-1");
        List<DeviceSummary> list = service.listDevices(ALICE, Channel.MOBILE);
        assertThat(list).hasSize(1);
        assertThat(list.getFirst().primary()).isTrue();
        assertThat(list.getFirst().deviceId()).isEqualTo(PHONE);
        assertThat(service.listDevices(new CustomerId("77777"), Channel.MOBILE)).isEmpty();
    }
}
