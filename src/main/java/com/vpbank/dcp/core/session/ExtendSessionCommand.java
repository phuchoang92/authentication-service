package com.vpbank.dcp.core.session;

import com.vpbank.dcp.core.domain.security.RequestKeyThumbprint;
import com.vpbank.dcp.core.port.out.session.SessionTokenLookup;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * What the Mobile BFF reports after it admitted one App request. {@code admissionId} is only
 * for correlation; it does not prove the BFF checked DPoP.
 */
public record ExtendSessionCommand(SessionTokenLookup lookup, RequestKeyThumbprint requestKey,
                                   String routeId, UUID admissionId, Instant admittedAt) {
    public ExtendSessionCommand {
        Objects.requireNonNull(lookup, "lookup");
        Objects.requireNonNull(requestKey, "requestKey");
        Objects.requireNonNull(routeId, "routeId");
        Objects.requireNonNull(admissionId, "admissionId");
        Objects.requireNonNull(admittedAt, "admittedAt");
    }
}
