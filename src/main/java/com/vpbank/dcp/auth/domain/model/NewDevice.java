package com.vpbank.dcp.auth.domain.model;

import java.time.Instant;
import lombok.Builder;
import lombok.NonNull;

/**
 * A device row about to be created for an installation: its ID, the key the installation presented and when.
 * Both ways a row is born use it: waiting for approval ({@link TrustedDevice#pending}) and trusted by the primary
 * enrollment ({@link TrustedDevice#trustedByEnrollment}).
 */
@Builder
public record NewDevice(@NonNull TrustedDeviceId id,
                        @NonNull DeviceInstallation installation,
                        @NonNull DeviceKey key,
                        @NonNull Instant createdAt) {
}
