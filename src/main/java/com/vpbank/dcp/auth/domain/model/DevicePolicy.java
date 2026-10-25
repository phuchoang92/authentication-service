package com.vpbank.dcp.auth.domain.model;

import java.time.Duration;
import java.util.Objects;

/**
 * Trusted-device policy (slice 4, 2026-10-25): trust lasts {@code trustDuration} (180 days), at
 * most {@code maxLiveDevices} (5) per customer and channel, and a login that still needs device
 * trust gets a restricted session of {@code restrictedSessionTtl} (10 min) with no absolute limit.
 */
public record DevicePolicy(Duration trustDuration, int maxLiveDevices, Duration restrictedSessionTtl) {
    public DevicePolicy {
        Objects.requireNonNull(trustDuration, "trustDuration");
        Objects.requireNonNull(restrictedSessionTtl, "restrictedSessionTtl");
        if (trustDuration.isNegative() || trustDuration.isZero() || maxLiveDevices < 1
                || restrictedSessionTtl.isNegative() || restrictedSessionTtl.isZero()) {
            throw new IllegalArgumentException("Device policy needs positive durations and at least one device");
        }
    }

    public static DevicePolicy standard() {
        return new DevicePolicy(Duration.ofDays(180), 5, Duration.ofMinutes(10));
    }
}
