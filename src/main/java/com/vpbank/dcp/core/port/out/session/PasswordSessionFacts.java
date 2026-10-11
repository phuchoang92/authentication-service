package com.vpbank.dcp.core.port.out.session;

import com.vpbank.dcp.core.domain.security.Digest32;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Frozen, current owner and key facts read before preparing a password session. */
public record PasswordSessionFacts(UUID operationId, UUID journeyId, UUID subjectId,
                                   String appId, UUID bindingId, Digest32 requestKey,
                                   String requestPublicJwk, String responsePublicJwk,
                                   Digest32 deviceKey, long customerSecurityVersion,
                                   long credentialSecurityVersion, long deviceSecurityVersion,
                                   long customerStatusVersion, Instant customerStatusValidUntil,
                                   String platformAssurance, boolean biometricLoginEnabled) {
    public PasswordSessionFacts {
        Objects.requireNonNull(operationId);
        Objects.requireNonNull(journeyId);
        Objects.requireNonNull(subjectId);
        Objects.requireNonNull(appId);
        Objects.requireNonNull(bindingId);
        Objects.requireNonNull(requestKey);
        Objects.requireNonNull(requestPublicJwk);
        Objects.requireNonNull(responsePublicJwk);
        Objects.requireNonNull(deviceKey);
        Objects.requireNonNull(customerStatusValidUntil);
        Objects.requireNonNull(platformAssurance);
    }
}
