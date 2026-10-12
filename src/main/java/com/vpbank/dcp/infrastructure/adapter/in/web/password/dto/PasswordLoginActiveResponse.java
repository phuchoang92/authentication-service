package com.vpbank.dcp.infrastructure.adapter.in.web.password.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** The seven top-level fields follow the public ACTIVE schema; nested metadata is cohesive. */
public record PasswordLoginActiveResponse(String status, String tokenEnvelope, String receipt,
        @JsonProperty("expires_in") long expiresIn, String scope, Session session, Security security)
        implements PasswordLoginResponse {
    public PasswordLoginActiveResponse {
        Objects.requireNonNull(status, "status");
        Objects.requireNonNull(tokenEnvelope, "tokenEnvelope");
        Objects.requireNonNull(receipt, "receipt");
        Objects.requireNonNull(scope, "scope");
        Objects.requireNonNull(session, "session");
        Objects.requireNonNull(security, "security");
    }

    @Override
    public String toString() { return "PasswordLoginActiveResponse[redacted]"; }

    public record Session(@JsonFormat(shape = JsonFormat.Shape.STRING) Instant idleExpiresAt,
                          @JsonFormat(shape = JsonFormat.Shape.STRING) Instant absoluteExpiresAt) {
        public Session {
            Objects.requireNonNull(idleExpiresAt, "idleExpiresAt");
            Objects.requireNonNull(absoluteExpiresAt, "absoluteExpiresAt");
        }
    }

    public record Security(boolean deviceTrusted, UUID deviceBindingId,
                           boolean biometricLoginEnabled, Assurance assurance) {
        public Security {
            Objects.requireNonNull(deviceBindingId, "deviceBindingId");
            Objects.requireNonNull(assurance, "assurance");
        }
    }

    public record Assurance(String devicePossession, String platformEvidence, String biometricEnforcement) {
        public Assurance {
            Objects.requireNonNull(devicePossession, "devicePossession");
            Objects.requireNonNull(platformEvidence, "platformEvidence");
            Objects.requireNonNull(biometricEnforcement, "biometricEnforcement");
        }
    }
}
