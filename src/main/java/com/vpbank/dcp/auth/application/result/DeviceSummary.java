package com.vpbank.dcp.auth.application.result;

import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.DevicePlatform;
import com.vpbank.dcp.auth.domain.model.DeviceStatus;
import com.vpbank.dcp.auth.domain.model.TrustLevel;
import lombok.Builder;

import java.time.Instant;

/** One device as the customer sees it. The web layer masks the device ID. */
@Builder
public record DeviceSummary(DeviceId deviceId, DevicePlatform platform, DeviceStatus status, TrustLevel trustLevel,
                            boolean primary, Instant trustedAt, Instant expiresAt, Instant lastLoginAt) { }
