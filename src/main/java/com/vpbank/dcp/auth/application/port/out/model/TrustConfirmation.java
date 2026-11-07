package com.vpbank.dcp.auth.application.port.out.model;

import com.vpbank.dcp.auth.domain.enums.PrimaryMode;
import com.vpbank.dcp.auth.domain.model.DeviceEnrollment;
import com.vpbank.dcp.auth.domain.model.SessionId;
import com.vpbank.dcp.auth.domain.model.TrustedDevice;
import com.vpbank.dcp.auth.domain.model.TrustedDeviceId;
import java.util.List;
import lombok.Builder;
import lombok.NonNull;

/**
 * Everything the trust commit writes in one SQL transaction (DD 20 §4, §7): the trusted row (new, or an
 * existing live row moved to trusted), the live row of the same installation it replaces (already
 * expired, may be null), the rows expired to respect the device cap, the completed enrollment, and how
 * the primary pointer is set. {@code receiptDigest} is the SHA-256 of the MFA receipt when the device
 * itself passed FACE (slice 5); {@code actorDeviceId} is the primary device that approved (slice 6).
 * {@code creationSessionId} is the restricted session that ran a primary enrollment whose row this commit writes
 * for the first time (slice 11: the transaction lived in the cache until now); null when the row already exists.
 */
@Builder
public record TrustConfirmation(@NonNull TrustedDevice device,
                                TrustedDevice replaced,
                                List<TrustedDevice> expiredByCap,
                                @NonNull DeviceEnrollment enrollment,
                                @NonNull PrimaryMode primaryMode,
                                boolean faceAuthenticated,
                                String receiptDigest,
                                TrustedDeviceId actorDeviceId,
                                SessionId creationSessionId) {
    public TrustConfirmation {
        expiredByCap = expiredByCap == null ? List.of() : List.copyOf(expiredByCap);
    }
}
