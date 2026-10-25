package com.vpbank.dcp.core.customer;

import java.util.Objects;
import java.util.UUID;

/**
 * The immutable owner this Auth service assigned to a verified provider identity.
 *
 * <p>This is Auth's own identifier and never leaves the service. It is not the Customer
 * domain's business identifier, which is a {@link CustomerNumber}. Both used to be called
 * {@code customerId}, and this one was also called {@code subjectId} and {@code ownerId};
 * the separate types exist so the two can no longer be confused or swapped.
 */
public record SubjectId(UUID value) {
    public SubjectId {
        Objects.requireNonNull(value, "value");
    }

    @Override
    public String toString() {
        return value.toString();
    }
}
