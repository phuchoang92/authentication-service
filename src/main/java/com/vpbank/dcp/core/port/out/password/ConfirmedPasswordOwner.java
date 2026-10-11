package com.vpbank.dcp.core.port.out.password;

import com.vpbank.dcp.core.domain.customer.CustomerAuthenticationState;
import com.vpbank.dcp.core.domain.customer.VerifiedProviderIdentity;
import java.util.Objects;
import java.util.UUID;

/** Durable owner from the original password operation, not current admission authority. */
public record ConfirmedPasswordOwner(VerifiedProviderIdentity identity,
                                     CustomerAuthenticationState customer,
                                     UUID subjectId) {

    public ConfirmedPasswordOwner {
        Objects.requireNonNull(identity, "identity");
        Objects.requireNonNull(customer, "customer");
        Objects.requireNonNull(subjectId, "subjectId");
    }
}
