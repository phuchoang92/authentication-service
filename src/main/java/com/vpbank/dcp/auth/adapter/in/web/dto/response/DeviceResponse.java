package com.vpbank.dcp.auth.adapter.in.web.dto.response;

import java.time.Instant;

/** One device in {@code GET /api/v1/devices}. {@code deviceId} is masked to its last four characters. */
public record DeviceResponse(String deviceId, String platform, String status, String trustLevel, boolean primary,
                             Instant trustedAt, Instant expiresAt, Instant lastLoginAt) { }
