package com.vpbank.dcp.auth.domain.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.vpbank.dcp.auth.domain.exception.DeviceStateException;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class TrustedDeviceTest {
    private static final Instant T0 = Instant.parse("2026-10-25T10:00:00Z");
    private final TrustedDevice device = TrustedDevice.trustedNow(TrustedDeviceId.random(), new CustomerId("90359"),
            Channel.MOBILE, new DeviceId("dev-1"), DevicePlatform.ANDROID, null, T0, DevicePolicy.standard());

    @Test
    void aDirectlyTrustedDeviceIsActiveTrustedFor180Days() {
        assertThat(device.status()).isEqualTo(DeviceStatus.ACTIVE);
        assertThat(device.trustLevel()).isEqualTo(TrustLevel.TRUSTED);
        assertThat(device.trustedAt()).isEqualTo(T0);
        assertThat(device.expiresAt()).isEqualTo(T0.plus(Duration.ofDays(180)));
        assertThat(device.isTrusted(T0.plus(Duration.ofDays(179)))).isTrue();
        assertThat(device.isTrusted(T0.plus(Duration.ofDays(180)))).isFalse();
    }

    @Test
    void loginUpdatesDisplayDataOnlyAndExpiryMakesTheRowHistory() {
        TrustedDevice later = device.recordLogin(T0.plusSeconds(60));
        assertThat(later.lastLoginAt()).isEqualTo(T0.plusSeconds(60));
        assertThat(later.expiresAt()).isEqualTo(device.expiresAt());
        assertThat(later.version()).isEqualTo(device.version());

        TrustedDevice expired = device.expire();
        assertThat(expired.status()).isEqualTo(DeviceStatus.EXPIRED);
        assertThat(expired.status().live()).isFalse();
        assertThat(expired.isTrusted(T0)).isFalse();
        assertThatThrownBy(expired::expire).isInstanceOf(DeviceStateException.class);
        assertThatThrownBy(() -> expired.recordLogin(T0)).isInstanceOf(DeviceStateException.class);
    }

    @Test
    void trustLevelAndTrustTimeComeTogether() {
        assertThatThrownBy(() -> device.toBuilder().trustedAt(null).build()).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> device.toBuilder().trustLevel(TrustLevel.NONE).build())
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new DevicePolicy(Duration.ZERO, 5, Duration.ofMinutes(10)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void aRestrictedSessionHasOneFixedTtlAndIsNeverExtended() {
        Session restricted = Session.startRestricted(SessionId.random(), new CustomerId("90359"), new DeviceId("dev-2"),
                Channel.MOBILE, T0, DevicePolicy.standard());
        assertThat(restricted.status()).isEqualTo(SessionStatus.NEED_TRUSTED_DEVICE);
        assertThat(restricted.idleExpiresAt()).isEqualTo(T0.plus(Duration.ofMinutes(10)));
        assertThat(restricted.absoluteExpiresAt()).isEqualTo(restricted.idleExpiresAt());
        assertThat(restricted.isLive(T0.plusSeconds(1))).isTrue();
        assertThat(restricted.isFull(T0.plusSeconds(1))).isFalse();
        SessionPolicy sessions = new SessionPolicy(Duration.ofMinutes(15), Duration.ofMinutes(20), Duration.ofSeconds(30));
        assertThatThrownBy(() -> restricted.extend(T0, T0, sessions)).isInstanceOf(
                com.vpbank.dcp.auth.domain.exception.SessionStateException.class);
        assertThat(restricted.end(T0).status()).isEqualTo(SessionStatus.ENDED);
    }
}
