package com.vpbank.dcp.infrastructure.adapter.out.persistence.repository.session;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.port.out.session.PasswordSessionFacts;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Current SQL facts; freshness is supplied by the adapter's domain policy. */
public record PasswordSessionFactsView(UUID operationId, UUID journeyId, UUID subjectId,
        String appId, UUID bindingId, Digest32 requestKey, String requestPublicJwk,
        String responsePublicJwk, Digest32 deviceKey, long customerSecurityVersion,
        long credentialSecurityVersion, long deviceSecurityVersion, long customerStatusVersion,
        Instant customerCheckedAt, String platformAssurance, boolean biometricLoginEnabled) {
    public PasswordSessionFactsView {
        Objects.requireNonNull(customerCheckedAt);
    }

    public PasswordSessionFacts toFacts(Instant customerStatusValidUntil) {
        return new PasswordSessionFacts(operationId, journeyId, subjectId, appId, bindingId,
                requestKey, requestPublicJwk, responsePublicJwk, deviceKey, customerSecurityVersion,
                credentialSecurityVersion, deviceSecurityVersion, customerStatusVersion,
                customerStatusValidUntil, platformAssurance, biometricLoginEnabled);
    }

    @Override
    public String toString() { return "PasswordSessionFactsView[redacted]"; }
}
