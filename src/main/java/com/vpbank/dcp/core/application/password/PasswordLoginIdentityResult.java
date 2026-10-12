package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.domain.customer.CustomerAuthenticationState;
import com.vpbank.dcp.core.domain.customer.VerifiedProviderIdentity;
import java.util.Objects;
import java.util.UUID;

/** An internal credential result, never a banking-login or session result. */
public sealed interface PasswordLoginIdentityResult {

    record Verified(VerifiedProviderIdentity identity,
                    CustomerAuthenticationState customer,
                    UUID subjectId) implements PasswordLoginIdentityResult {
        public Verified {
            Objects.requireNonNull(identity, "identity");
            Objects.requireNonNull(customer, "customer");
            Objects.requireNonNull(subjectId, "subjectId");
        }
    }

    record Rejected() implements PasswordLoginIdentityResult { }

    record Processing() implements PasswordLoginIdentityResult { }

    record MfaUnavailable() implements PasswordLoginIdentityResult { }

    record NotClaimable() implements PasswordLoginIdentityResult { }

    record Conflict() implements PasswordLoginIdentityResult { }

    record AuthorityClosed() implements PasswordLoginIdentityResult { }
}
