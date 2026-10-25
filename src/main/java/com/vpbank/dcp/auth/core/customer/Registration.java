package com.vpbank.dcp.auth.core.customer;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * One registration request as stored. The Keycloak issuer and subject are known from
 * USER_CREATED on; before that they are null.
 */
public record Registration(UUID requestId, String customerId, String userName,
                           RequestDigest requestDigest, RegistrationState state,
                           String identityIssuer, String identitySubject,
                           Instant expiresAt, long version) {
    public Registration {
        Objects.requireNonNull(requestId, "requestId");
        Objects.requireNonNull(customerId, "customerId");
        Objects.requireNonNull(userName, "userName");
        Objects.requireNonNull(requestDigest, "requestDigest");
        Objects.requireNonNull(state, "state");
        Objects.requireNonNull(expiresAt, "expiresAt");
        if ((identityIssuer == null) != (identitySubject == null)) {
            throw new IllegalArgumentException("Identity issuer and subject are set together");
        }
    }
}
