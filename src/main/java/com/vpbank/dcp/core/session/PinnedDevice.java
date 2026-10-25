package com.vpbank.dcp.core.session;

import java.util.Objects;
import java.util.Set;

/** The App channel and platform a restricted login came from, and the device it is trusting. */
public record PinnedDevice(String channel, String platform, TrustTarget target) {
    private static final Set<String> PLATFORMS = Set.of("ANDROID", "IOS");

    public PinnedDevice {
        Objects.requireNonNull(target, "target");
        if (channel == null || channel.isBlank() || channel.length() > 64
                || !PLATFORMS.contains(platform)) {
            throw new IllegalArgumentException("Invalid restricted session value");
        }
    }
}
