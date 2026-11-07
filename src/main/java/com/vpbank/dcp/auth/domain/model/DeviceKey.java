package com.vpbank.dcp.auth.domain.model;

import com.vpbank.dcp.auth.domain.enums.DevicePlatform;
import lombok.NonNull;

/**
 * The key a device asks to be trusted with: its public JWK and the platform that keeps the private part.
 */
public record DeviceKey(@NonNull String publicJwk, @NonNull DevicePlatform platform) {
}
