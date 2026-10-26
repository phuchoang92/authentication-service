package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.response;

import java.time.Instant;

/** One installation waiting for the primary device's approval; the device ID is shown masked. */
public record PendingDeviceResponse(String enrollmentId, String deviceId, String platform, String status, Instant expiresAt) { }
