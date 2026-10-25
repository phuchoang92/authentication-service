package com.vpbank.dcp.auth.application.result;

import com.vpbank.dcp.auth.domain.enums.DevicePlatform;
import com.vpbank.dcp.auth.domain.enums.DeviceStatus;
import com.vpbank.dcp.auth.domain.enums.TrustLevel;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import java.time.Instant;
import lombok.Builder;

/** One device as the customer sees it. The web layer masks the device ID. */
@Builder
public record DeviceSummary(DeviceId deviceId, DevicePlatform platform, DeviceStatus status, TrustLevel trustLevel,
                            boolean primary, Instant trustedAt, Instant expiresAt, Instant lastLoginAt) { }
