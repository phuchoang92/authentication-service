package com.vpbank.dcp.core.application.password;

import java.util.Objects;
import java.util.UUID;

public sealed interface PasswordAdmissionResult {

    record Reserved(UUID operationId, UUID journeyId) implements PasswordAdmissionResult {
        public Reserved {
            Objects.requireNonNull(operationId, "operationId");
            Objects.requireNonNull(journeyId, "journeyId");
        }
    }

    record Existing(UUID operationId, UUID journeyId) implements PasswordAdmissionResult {
        public Existing {
            Objects.requireNonNull(operationId, "operationId");
            Objects.requireNonNull(journeyId, "journeyId");
        }
    }

    record Rejected() implements PasswordAdmissionResult { }

    record Conflict() implements PasswordAdmissionResult { }

    record AuthorityClosed() implements PasswordAdmissionResult { }
}
