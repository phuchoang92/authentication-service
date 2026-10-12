package com.vpbank.dcp.core.application.password;

import java.util.Objects;
import java.util.UUID;

public sealed interface PasswordLoginReservationResult {

    record Reserved(UUID operationId, UUID journeyId) implements PasswordLoginReservationResult {
        public Reserved {
            Objects.requireNonNull(operationId, "operationId");
            Objects.requireNonNull(journeyId, "journeyId");
        }
    }

    record Existing(UUID operationId, UUID journeyId) implements PasswordLoginReservationResult {
        public Existing {
            Objects.requireNonNull(operationId, "operationId");
            Objects.requireNonNull(journeyId, "journeyId");
        }
    }

    record Rejected() implements PasswordLoginReservationResult { }

    record Conflict() implements PasswordLoginReservationResult { }

    record AuthorityClosed() implements PasswordLoginReservationResult { }
}
