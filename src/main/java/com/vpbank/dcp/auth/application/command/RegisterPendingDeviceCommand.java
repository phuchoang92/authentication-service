package com.vpbank.dcp.auth.application.command;

import com.vpbank.dcp.auth.domain.enums.DevicePlatform;
import com.vpbank.dcp.auth.domain.model.AdmittedSession;
import com.vpbank.dcp.auth.domain.model.EnrollmentPolicy;
import lombok.Builder;
import lombok.NonNull;

/**
 * A new installation asks to wait for the primary device's approval (slice 6), from its restricted session.
 * {@code devicePublicJwk} and {@code platform} are what an unknown installation sends; they are null for a known
 * one, whose live row keeps what Auth already stores. The policy bounds how many devices may wait and how long.
 */
@Builder
public record RegisterPendingDeviceCommand(@NonNull AdmittedSession newDeviceSession,
                                           String devicePublicJwk,
                                           DevicePlatform platform,
                                           @NonNull EnrollmentPolicy enrollmentPolicy,
                                           @NonNull String correlationId) {
}
