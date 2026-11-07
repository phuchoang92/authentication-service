package com.vpbank.dcp.auth.domain.model;

import com.vpbank.dcp.auth.domain.enums.ServiceScope;
import java.time.Instant;
import java.util.UUID;
import lombok.Builder;
import lombok.NonNull;

/**
 * What a service token says (slice 12), before it is signed: who issued it ({@code iss}), which service asked
 * for it ({@code sub}), who may accept it ({@code aud}), what it allows ({@code scope}), the business journey
 * it belongs to ({@code businessReference}, present exactly when the scope requires one), and its lifetime
 * ({@code iat}, {@code exp}, {@code jti}). The signer renders these claims; nothing else goes into the token.
 *
 * @param businessReference null when the scope does not require one
 */
@Builder
public record ServiceTokenClaims(@NonNull String issuer,
                                 @NonNull ServiceId issuedTo,
                                 @NonNull String audience,
                                 @NonNull ServiceScope scope,
                                 BusinessReference businessReference,
                                 @NonNull Instant issuedAt,
                                 @NonNull Instant expiresAt,
                                 @NonNull UUID tokenId) {
    public ServiceTokenClaims {
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
