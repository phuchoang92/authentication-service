package com.vpbank.dcp.auth.application.port.out.model;

import com.vpbank.dcp.auth.domain.enums.PrimaryMode;
import com.vpbank.dcp.auth.domain.model.DeviceEnrollment;
import com.vpbank.dcp.auth.domain.model.SessionId;
import com.vpbank.dcp.auth.domain.model.TrustedDevice;
import com.vpbank.dcp.auth.domain.model.TrustedDeviceId;
import lombok.Builder;
import lombok.NonNull;

/**
 * The verified candidate, completed enrollment and intended primary mode. The commit reevaluates the
 * enrollment's pinned binding and applies the device cap to the locked rows. {@code receiptDigest}
 * is the SHA-256 of the MFA receipt when the device
 * itself passed FACE (slice 5); {@code actorDeviceId} is the primary device that approved (slice 6).
 * {@code creationSessionId} is the restricted session that ran a primary enrollment whose row this commit writes
 * for the first time (slice 11: the transaction lived in the cache until now); null when the row already exists.
 */
@Builder
public record TrustConfirmation(@NonNull TrustedDevice device,
                                @NonNull DeviceEnrollment enrollment,
                                @NonNull PrimaryMode primaryMode,
                                boolean faceAuthenticated,
                                String receiptDigest,
                                TrustedDeviceId actorDeviceId,
                                SessionId creationSessionId) {
}
