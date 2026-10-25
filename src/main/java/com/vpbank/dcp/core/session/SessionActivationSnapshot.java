package com.vpbank.dcp.core.session;

import java.util.Objects;

/**
 * Confirmed source data for activation; all groups participate in locked revalidation.
 * Assurance and biometric availability describe separate properties of this snapshot.
 */
public record SessionActivationSnapshot(SessionActivationContext context,
                                        SessionKeyBindings keys,
                                        SessionSecurityVersions securityVersions,
                                        CustomerStatusFreshness customerStatus,
                                        SessionAssurance assurance,
                                        boolean biometricLoginEnabled) {
    public SessionActivationSnapshot {
        Objects.requireNonNull(context, "context");
        Objects.requireNonNull(keys, "keys");
        Objects.requireNonNull(securityVersions, "securityVersions");
        Objects.requireNonNull(customerStatus, "customerStatus");
        Objects.requireNonNull(assurance, "assurance");
    }

    @Override
    public String toString() {
        return "SessionActivationSnapshot[redacted]";
    }
}
