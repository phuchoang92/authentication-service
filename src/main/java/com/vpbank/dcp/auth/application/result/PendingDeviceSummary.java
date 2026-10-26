package com.vpbank.dcp.auth.application.result;

import com.vpbank.dcp.auth.domain.enums.DevicePlatform;
import com.vpbank.dcp.auth.domain.enums.EnrollmentState;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import java.time.Instant;

/** One installation waiting for the primary device's approval, as the primary device sees it (slice 6). */
public record PendingDeviceSummary(EnrollmentId enrollmentId, DeviceId deviceId, DevicePlatform platform,
                                   EnrollmentState state, Instant expiresAt) { }
