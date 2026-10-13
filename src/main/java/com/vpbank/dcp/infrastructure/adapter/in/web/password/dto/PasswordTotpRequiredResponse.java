package com.vpbank.dcp.infrastructure.adapter.in.web.password.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import java.time.Instant;
import java.util.Objects;

/** Only a restricted encrypted token leaves Auth; no banking session is created. */
public record PasswordTotpRequiredResponse(String status, String authenticationId,
                                           Challenge challenge, String tokenEnvelope,
                                           String receipt, String scope)
        implements PasswordLoginResponse {
    public PasswordTotpRequiredResponse {
        Objects.requireNonNull(status);
        Objects.requireNonNull(authenticationId);
        Objects.requireNonNull(challenge);
        Objects.requireNonNull(tokenEnvelope);
        Objects.requireNonNull(receipt);
        Objects.requireNonNull(scope);
    }

    @Override
    public String toString() {
        return "PasswordTotpRequiredResponse[redacted]";
    }

    public record Challenge(String challengeId, String method,
                            @JsonFormat(shape = JsonFormat.Shape.STRING) Instant expiresAt) { }
}
