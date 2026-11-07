package com.vpbank.dcp.auth.application.command;

import com.vpbank.dcp.auth.domain.model.DeviceEnrollment;
import com.vpbank.dcp.auth.domain.model.DeviceKey;
import com.vpbank.dcp.auth.domain.model.SessionId;
import lombok.Builder;
import lombok.NonNull;

/**
 * The primary enrollment passed FACE (DD 20 §4): the enrollment row as the commit first writes it, the restricted
 * session that ran it, the device key it proved, and the MFA receipt digest kept with the trust.
 */
@Builder
public record ConfirmTrustCommand(@NonNull DeviceEnrollment enrollment,
                                  @NonNull SessionId restrictedSessionId,
                                  @NonNull DeviceKey deviceKey,
                                  @NonNull String receiptDigest,
                                  @NonNull String correlationId) {
    @Override
    public String toString() {
        return "ConfirmTrustCommand[enrollmentId=" + enrollment.id() + ", redacted]";
    }
}
