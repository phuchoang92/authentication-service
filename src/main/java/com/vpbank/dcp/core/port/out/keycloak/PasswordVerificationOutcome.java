package com.vpbank.dcp.core.port.out.keycloak;

import com.vpbank.dcp.core.domain.customer.VerifiedProviderIdentity;
import java.util.Objects;

public sealed interface PasswordVerificationOutcome {

    record Verified(VerifiedProviderIdentity identity) implements PasswordVerificationOutcome {
        public Verified {
            Objects.requireNonNull(identity, "identity");
        }
    }

    record Rejected() implements PasswordVerificationOutcome {
    }
}
