package com.vpbank.dcp.core.port.out.password;

import java.time.Instant;
import java.util.Objects;

/** Immutable facts committed before a password can be sent to Keycloak. */
public record PasswordReservation(PasswordOperationContext operation,
                                  VerifiedPasswordProofs proofs,
                                  PasswordReservationFingerprints fingerprints,
                                  Instant now,
                                  Instant credentialDeadline,
                                  Instant journeyDeadline) {

    public PasswordReservation {
        Objects.requireNonNull(operation, "operation");
        Objects.requireNonNull(proofs, "proofs");
        Objects.requireNonNull(fingerprints, "fingerprints");
        Objects.requireNonNull(now, "now");
        Objects.requireNonNull(credentialDeadline, "credentialDeadline");
        Objects.requireNonNull(journeyDeadline, "journeyDeadline");
        if (!credentialDeadline.isAfter(now) || !journeyDeadline.isAfter(credentialDeadline)) {
            throw new InvalidPasswordOperationException();
        }
    }
}
