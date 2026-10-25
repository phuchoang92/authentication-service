package com.vpbank.dcp.core.session;

import com.vpbank.dcp.core.security.RequestKeyThumbprint;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * What the Mobile BFF reports after it admitted one App request. {@code admissionId} is only
 * for correlation; it does not prove the BFF checked DPoP.
 */
public record ExtendSessionCommand(UUID sessionId, RequestKeyThumbprint requestKey,
                                   String routeId, UUID admissionId, Instant admittedAt) {
    public ExtendSessionCommand {
        Objects.requireNonNull(sessionId, "sessionId");
        Objects.requireNonNull(requestKey, "requestKey");
        Objects.requireNonNull(routeId, "routeId");
        Objects.requireNonNull(admissionId, "admissionId");
        Objects.requireNonNull(admittedAt, "admittedAt");
    }
}
