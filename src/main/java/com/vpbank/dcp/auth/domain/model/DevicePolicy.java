package com.vpbank.dcp.auth.domain.model;

import java.time.Duration;
import java.util.Comparator;
import java.util.List;
import lombok.NonNull;

/**
 * Trusted-device policy (slice 4, 2026-10-25): trust lasts {@code trustDuration} (180 days), at
 * most {@code maxLiveDevices} (5) per customer and channel, and a login that still needs device
 * trust gets a restricted session of {@code restrictedSessionTtl} (10 min) with no absolute limit.
 */
public record DevicePolicy(@NonNull Duration trustDuration,
                           int maxLiveDevices,
                           @NonNull Duration restrictedSessionTtl) {
    private static final Comparator<TrustedDevice> OLDEST_LOGIN_FIRST = Comparator.comparing(
            TrustedDevice::lastLoginAt, Comparator.nullsFirst(Comparator.naturalOrder()));

    public DevicePolicy {
        if (trustDuration.isNegative() || trustDuration.isZero() || maxLiveDevices < 1
                || restrictedSessionTtl.isNegative() || restrictedSessionTtl.isZero()) {
            throw new IllegalArgumentException("Device policy needs positive durations and at least one device");
        }
    }

    public static DevicePolicy standard() {
        return new DevicePolicy(Duration.ofDays(180), 5, Duration.ofMinutes(10));
    }

    /** Selects the least recently used bindings to retire when admitting one binding. */
    public List<TrustedDevice> bindingsBeyondCap(List<TrustedDevice> otherBindings) {
        int excess = Math.max(0, otherBindings.size() + 1 - maxLiveDevices);
        return otherBindings.stream()
                .sorted(OLDEST_LOGIN_FIRST.thenComparing(device -> device.id().value()))
                .limit(excess)
                .toList();
    }
}
