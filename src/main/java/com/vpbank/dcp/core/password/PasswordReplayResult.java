package com.vpbank.dcp.core.password;

import java.util.Objects;
import java.util.UUID;

public sealed interface PasswordReplayResult {

    record Reserved(UUID generation) implements PasswordReplayResult {
        public Reserved {
            Objects.requireNonNull(generation, "generation");
        }
    }

    record Replayed() implements PasswordReplayResult { }

    record AuthorityClosed() implements PasswordReplayResult { }
}
