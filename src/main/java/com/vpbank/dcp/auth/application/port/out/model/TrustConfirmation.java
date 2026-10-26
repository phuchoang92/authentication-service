package com.vpbank.dcp.auth.application.port.out.model;

import com.vpbank.dcp.auth.domain.enums.PrimaryMode;
import com.vpbank.dcp.auth.domain.model.DeviceEnrollment;
import com.vpbank.dcp.auth.domain.model.TrustedDevice;
import com.vpbank.dcp.auth.domain.model.TrustedDeviceId;
import java.util.List;
import java.util.Objects;
import lombok.Builder;

/**
 * Everything the trust commit writes in one SQL transaction (DD 20 §4, §7): the trusted row (new, or an
 * existing live row moved to trusted), the live row of the same installation it replaces (already
 * expired, may be null), the rows expired to respect the device cap, the completed enrollment, and how
 * the primary pointer is set. {@code receiptDigest} is the SHA-256 of the MFA receipt when the device
 * itself passed FACE (slice 5); {@code actorDeviceId} is the primary device that approved (slice 6).
 */
@Builder
public record TrustConfirmation(TrustedDevice device, TrustedDevice replaced, List<TrustedDevice> expiredByCap,
                                DeviceEnrollment enrollment, PrimaryMode primaryMode, boolean faceAuthenticated,
                                String receiptDigest, TrustedDeviceId actorDeviceId) {
    public TrustConfirmation {
        Objects.requireNonNull(device, "device");
        Objects.requireNonNull(enrollment, "enrollment");
        Objects.requireNonNull(primaryMode, "primaryMode");
        expiredByCap = expiredByCap == null ? List.of() : List.copyOf(expiredByCap);
    }
}
