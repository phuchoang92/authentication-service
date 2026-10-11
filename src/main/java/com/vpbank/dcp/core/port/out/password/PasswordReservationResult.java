package com.vpbank.dcp.core.port.out.password;

import com.vpbank.dcp.core.domain.security.Digest32;
import java.util.Objects;
import java.util.UUID;

/** A duplicate exposes only the stored digest selector, never the password. */
public sealed interface PasswordReservationResult {

    record Created(UUID journeyId) implements PasswordReservationResult {
        public Created {
            Objects.requireNonNull(journeyId, "journeyId");
        }
    }

    record Existing(UUID operationId, UUID journeyId, Digest32 commandDigest,
                    String commandKeyId) implements PasswordReservationResult {
        public Existing {
            Objects.requireNonNull(operationId, "operationId");
            Objects.requireNonNull(journeyId, "journeyId");
            Objects.requireNonNull(commandDigest, "commandDigest");
            Objects.requireNonNull(commandKeyId, "commandKeyId");
        }
    }

    record Conflict() implements PasswordReservationResult { }
}
