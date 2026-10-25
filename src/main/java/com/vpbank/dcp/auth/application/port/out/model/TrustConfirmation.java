package com.vpbank.dcp.auth.application.port.out.model;

import com.vpbank.dcp.auth.domain.model.DeviceEnrollment;
import com.vpbank.dcp.auth.domain.model.TrustedDevice;
import java.util.List;
import java.util.Objects;
import lombok.Builder;

/**
 * Everything one confirmed enrollment changes, written in one transaction: the new trusted row,
 * the previous live row of the same installation (replaced, may be null), rows pushed out by the
 * device cap, the enrollment in its COMPLETED state, and the SHA-256 of the MFA receipt for audit.
 */
@Builder
public record TrustConfirmation(TrustedDevice device, TrustedDevice replaced, List<TrustedDevice> expiredByCap,
                                DeviceEnrollment enrollment, String receiptDigest) {
    public TrustConfirmation {
        Objects.requireNonNull(device, "device");
        Objects.requireNonNull(enrollment, "enrollment");
        Objects.requireNonNull(receiptDigest, "receiptDigest");
        expiredByCap = expiredByCap == null ? List.of() : List.copyOf(expiredByCap);
    }
}
