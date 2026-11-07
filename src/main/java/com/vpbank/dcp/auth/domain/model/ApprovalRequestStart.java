package com.vpbank.dcp.auth.domain.model;

import java.time.Instant;
import lombok.Builder;
import lombok.NonNull;

/**
 * What a new installation's approval request starts with (slice 6): the enrollment, the requesting installation,
 * the device row the approval will trust (the PENDING row, or the live row of a known installation) and the end
 * of the approval window.
 */
@Builder
public record ApprovalRequestStart(@NonNull EnrollmentId enrollmentId,
                                   @NonNull DeviceInstallation requester,
                                   @NonNull TrustedDeviceId targetDeviceId,
                                   @NonNull Instant expiresAt) {
}
