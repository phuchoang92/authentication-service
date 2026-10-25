package com.vpbank.dcp.auth.application.command;

import lombok.Builder;

import java.time.Instant;
import java.util.Objects;

/**
 * The BFF names the session by its lookup (key version + base64url HMAC digest), never by the
 * token or the internal session ID. {@code admittedAt} is when the BFF admitted the request;
 * {@code routeId} and {@code admissionId} are correlation.
 */
@Builder
public record ExtendSessionCommand(String lookupKeyVersion, String lookupDigest, Instant admittedAt,
                                   String routeId, String admissionId) {
    public ExtendSessionCommand {
        Objects.requireNonNull(lookupKeyVersion, "lookupKeyVersion");
        Objects.requireNonNull(lookupDigest, "lookupDigest");
        Objects.requireNonNull(admittedAt, "admittedAt");
        Objects.requireNonNull(routeId, "routeId");
    }
}
