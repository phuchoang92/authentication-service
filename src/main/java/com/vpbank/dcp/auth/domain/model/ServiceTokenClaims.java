package com.vpbank.dcp.auth.domain.model;

import com.vpbank.dcp.auth.domain.enums.ServiceScope;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import lombok.Builder;

/**
 * What a service token says (slice 12), before it is signed: who issued it ({@code iss}), which service asked
 * for it ({@code sub}), who may accept it ({@code aud}), what it allows ({@code scope}), the business journey
 * it belongs to ({@code businessReference}, present exactly when the scope requires one), and its lifetime
 * ({@code iat}, {@code exp}, {@code jti}). The signer renders these claims; nothing else goes into the token.
 *
 * @param businessReference null when the scope does not require one
 */
@Builder
public record ServiceTokenClaims(String issuer, ServiceId caller, String audience, ServiceScope scope,
                                 BusinessReference businessReference, Instant issuedAt, Instant expiresAt,
                                 UUID tokenId) {
    public ServiceTokenClaims {
        Objects.requireNonNull(issuer, "issuer");
        Objects.requireNonNull(caller, "caller");
        Objects.requireNonNull(audience, "audience");
        Objects.requireNonNull(scope, "scope");
        Objects.requireNonNull(issuedAt, "issuedAt");
        Objects.requireNonNull(expiresAt, "expiresAt");
        Objects.requireNonNull(tokenId, "tokenId");
        if (issuer.isBlank() || audience.isBlank()) {
            throw new IllegalArgumentException("Issuer and audience are required");
        }
        if (!expiresAt.isAfter(issuedAt)) {
            throw new IllegalArgumentException("A token expires after it is issued");
        }
        if (scope.businessReferenceRequired() != (businessReference != null)) {
            throw new IllegalArgumentException("Scope " + scope + " and business reference do not go together");
        }
    }
}
