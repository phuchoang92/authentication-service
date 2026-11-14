package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.domain.model.DeviceInstallation;
import com.vpbank.dcp.auth.domain.model.DomainFixtures;
import com.vpbank.dcp.auth.application.command.RouteAfterPasswordCommand;
import com.vpbank.dcp.auth.application.command.ConfirmTrustCommand;
import com.vpbank.dcp.auth.domain.model.EnrollmentTransaction;
import com.vpbank.dcp.auth.domain.model.DeviceKey;
import com.vpbank.dcp.auth.domain.model.KeyExchangeStart;
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
        assertThat(service.routeAfterPassword(passwordLogin(Channel.MOBILE, PHONE), ANY_KEY))
                .isInstanceOf(DeviceRouting.NeedTrust.class);
        assertThat(devices.rows).isEmpty();
        assertThat(devices.findPrimary(ALICE, Channel.MOBILE)).isEmpty();

        seedTrustedPrimary(PHONE, DevicePlatform.ANDROID);
        assertThat(service.routeAfterPassword(passwordLogin(Channel.MOBILE, TABLET), ANY_KEY))
                .isInstanceOf(DeviceRouting.NeedTrust.class);
        assertThat(devices.rows).hasSize(1);
    }

    @Test
    void thePrimaryDeviceThatProvesItsKeyGetsAFullSessionAndItsLastLoginIsRecorded() {
        TrustedDevice phone = seedTrustedPrimary(PHONE, DevicePlatform.ANDROID);
        TrustedDeviceService later = new TrustedDeviceService(devices, DevicePolicy.standard(), TrustedDeviceId::random,
                Clock.fixed(NOW.plusSeconds(600), ZoneOffset.UTC));

        DevicePossession phoneKeyProven = device -> device.id().equals(phone.id());
        assertThat(later.routeAfterPassword(passwordLogin(Channel.MOBILE, PHONE), phoneKeyProven))
                .isInstanceOf(DeviceRouting.FullSession.class);
        assertThat(devices.only().lastLoginAt()).isEqualTo(NOW.plusSeconds(600));
        assertThat(devices.only().version()).isEqualTo(1);
    }

    /** Slice 13: the primary device that cannot prove its key (reinstall, copied ID) is routed to the trust flow. */
    @Test
    void thePrimaryDeviceThatCannotProveItsKeyNeedsTrustAndNothingIsRecorded() {
        seedTrustedPrimary(PHONE, DevicePlatform.ANDROID);

        assertThat(service.routeAfterPassword(passwordLogin(Channel.MOBILE, PHONE), NO_KEY))
                .isInstanceOf(DeviceRouting.NeedTrust.class);
        assertThat(devices.only().lastLoginAt()).isEqualTo(NOW);
        assertThat(devices.only().version()).isZero();
    }

    @Test
    void aTrustedButNotPrimaryOrExpiredDeviceNeedsTrustBeforeTheKeyIsEvenAsked() {
        TrustedDevice phone = seedTrustedPrimary(PHONE, DevicePlatform.ANDROID);
        TrustedDevice tablet = DomainFixtures.trustedDevice(new DeviceInstallation(ALICE, Channel.MOBILE, TABLET),
                DevicePlatform.IOS, null, NOW);
        devices.rows.put(tablet.id(), tablet); // trusted by a later flow, but the phone stays primary
        List<TrustedDevice> asked = new java.util.ArrayList<>();
        DevicePossession recording = device -> asked.add(device);

        assertThat(service.routeAfterPassword(passwordLogin(Channel.MOBILE, TABLET), recording))
                .isInstanceOf(DeviceRouting.NeedTrust.class);

        TrustedDeviceService muchLater = new TrustedDeviceService(devices, DevicePolicy.standard(), TrustedDeviceId::random,
                Clock.fixed(NOW.plus(Duration.ofDays(181)), ZoneOffset.UTC));
        assertThat(muchLater.routeAfterPassword(passwordLogin(Channel.MOBILE, PHONE), recording))
                .isInstanceOf(DeviceRouting.NeedTrust.class);
        assertThat(asked).isEmpty();
        assertThat(devices.rows.get(phone.id()).status()).isEqualTo(DeviceStatus.ACTIVE); // expiry is judged, not written here
    }

    @Test
    void webHasNoDeviceTrust() {
        assertThat(service.routeAfterPassword(passwordLogin(Channel.WEB, null), NO_KEY))
                .isInstanceOf(DeviceRouting.FullSession.class);
        assertThat(devices.rows).isEmpty();
    }

    @Test
    void confirmTrustReplacesTheSameInstallationEnforcesTheCapAndMakesTheDevicePrimary() {
        for (int i = 0; i < 5; i++) {
            DeviceInstallation installation = new DeviceInstallation(ALICE, Channel.MOBILE, new DeviceId("d" + i));
            TrustedDevice d = DomainFixtures.trustedDevice(installation, DevicePlatform.ANDROID, null,
                    NOW.minus(Duration.ofDays(i)));
            devices.rows.put(d.id(), d);
        }
        TrustedDevice oldTablet = DomainFixtures.trustedDevice(new DeviceInstallation(ALICE, Channel.MOBILE, TABLET),
                DevicePlatform.IOS, "{old}", NOW.minus(Duration.ofDays(9)));
        devices.rows.put(oldTablet.id(), oldTablet);
        com.vpbank.dcp.auth.domain.model.SessionId restrictedSession = com.vpbank.dcp.auth.domain.model.SessionId.random();
        com.vpbank.dcp.auth.domain.model.AdmittedSession tabletSession = new com.vpbank.dcp.auth.domain.model.AdmittedSession(
                restrictedSession, ALICE, Channel.MOBILE, TABLET, com.vpbank.dcp.auth.domain.enums.SessionStatus.NEED_TRUSTED_DEVICE);
        KeyExchangeStart start = KeyExchangeStart.builder()
                .enrollmentId(com.vpbank.dcp.auth.domain.model.EnrollmentId.random())
                .newDeviceSession(tabletSession)
                .targetDeviceId(oldTablet.id())
                .deviceKey(new DeviceKey("{new}", DevicePlatform.IOS))
                .serverPublicJwk("{srv-pub}")
                .serverPrivateJwk("{srv-priv}")
                .challengeDigest("digest")
                .sealedChallenge("jwe.challenge")
                .build();
        EnrollmentTransaction passed = EnrollmentTransaction.keyExchange(start).markMfaRequired("mfa-1", NOW.plusSeconds(300));
        com.vpbank.dcp.auth.domain.model.DeviceEnrollment enrollment =
                com.vpbank.dcp.auth.domain.model.DeviceEnrollment.fromTransaction(passed, NOW.plusSeconds(600));

        ConfirmTrustCommand trust = ConfirmTrustCommand.builder()
                .enrollment(enrollment)
                .restrictedSessionId(restrictedSession)
                .deviceKey(new DeviceKey("{new}", DevicePlatform.IOS))
                .receiptDigest("receipt")
                .correlationId("corr-c")
                .build();
        TrustedDevice trusted = service.confirmTrust(trust).orElseThrow();

        assertThat(trusted.publicKey()).isEqualTo("{new}");
        assertThat(devices.rows).doesNotContainKey(oldTablet.id()).hasSize(5);
        assertThat(devices.findLive(ALICE, Channel.MOBILE, new DeviceId("d4"))).isEmpty();
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
        TrustedDevice device = DomainFixtures.trustedDevice(new DeviceInstallation(ALICE, Channel.MOBILE, deviceId),
                platform, "{\"alg\":\"ML-DSA-65\",\"kty\":\"AKP\",\"pub\":\"" + deviceId.value() + "\"}", NOW);
        devices.rows.put(device.id(), device);
        devices.primaries.put(new InMemoryTrustedDeviceRepository.Key(ALICE, Channel.MOBILE), device.id());
        return device;
    }

    /** Alice's login on this channel and installation, as the login hands it to the device routing. */
    private static RouteAfterPasswordCommand passwordLogin(Channel channel, DeviceId deviceId) {
        return RouteAfterPasswordCommand.builder()
                .customerId(ALICE)
                .channel(channel)
                .deviceId(deviceId)
                .build();
    }
}
