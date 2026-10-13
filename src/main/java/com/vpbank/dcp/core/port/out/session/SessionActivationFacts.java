package com.vpbank.dcp.core.port.out.session;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.session.SessionAssurance;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Frozen, current owner and key facts read before preparing a session. */
public record SessionActivationFacts(UUID operationId, UUID journeyId, UUID subjectId,
                                   String appId, UUID bindingId, Digest32 requestKey,
                                   String requestPublicJwk, String responsePublicJwk,
                                   Digest32 deviceKey, long customerSecurityVersion,
                                   long credentialSecurityVersion, long deviceSecurityVersion,
                                   long customerStatusVersion, Instant customerStatusValidUntil,
                                   SessionAssurance assurance, boolean biometricLoginEnabled) {
    public SessionActivationFacts {
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
        Objects.requireNonNull(assurance);
    }
}
