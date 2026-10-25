package com.vpbank.dcp.auth.application.result;

import com.vpbank.dcp.auth.domain.enums.DevicePlatform;
import com.vpbank.dcp.auth.domain.model.TrustedDeviceId;

/** What TrustedDeviceService publishes about a live installation to other services: never the aggregate. */
public record KnownDeviceSummary(TrustedDeviceId id, DevicePlatform platform, String publicKey) { }
