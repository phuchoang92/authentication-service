package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.domain.customer.CustomerAuthenticationState;
import com.vpbank.dcp.core.domain.customer.VerifiedProviderIdentity;
import java.util.Objects;
import java.util.UUID;

/** An internal credential result, never a banking-login or session result. */
public sealed interface PasswordCredentialCheckResult {

    record Verified(VerifiedProviderIdentity identity,
                    CustomerAuthenticationState customer,
                    UUID subjectId) implements PasswordCredentialCheckResult {
        public Verified {
            Objects.requireNonNull(identity, "identity");
            Objects.requireNonNull(customer, "customer");
            Objects.requireNonNull(subjectId, "subjectId");
        }
    }

    record Rejected() implements PasswordCredentialCheckResult { }

    record Processing() implements PasswordCredentialCheckResult { }

    record MfaUnavailable() implements PasswordCredentialCheckResult { }

    record NotClaimable() implements PasswordCredentialCheckResult { }

    record Conflict() implements PasswordCredentialCheckResult { }

    record AuthorityClosed() implements PasswordCredentialCheckResult { }
}
