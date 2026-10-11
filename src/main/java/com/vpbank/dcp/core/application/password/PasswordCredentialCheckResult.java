package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.domain.customer.VerifiedProviderIdentity;
import java.util.Objects;

/** An internal credential result, never a banking-login or session result. */
public sealed interface PasswordCredentialCheckResult {

    record Verified(VerifiedProviderIdentity identity) implements PasswordCredentialCheckResult {
        public Verified {
            Objects.requireNonNull(identity, "identity");
        }
    }

    record Rejected() implements PasswordCredentialCheckResult { }

    record Processing() implements PasswordCredentialCheckResult { }

    record NotClaimable() implements PasswordCredentialCheckResult { }
}
