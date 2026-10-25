package com.vpbank.dcp.auth.application.port.in;

import java.time.Instant;
import java.util.Objects;

public sealed interface ExtendSessionResult {
    record Extended(Instant idleExpiresAt, Instant absoluteExpiresAt) implements ExtendSessionResult {
        public Extended {
            Objects.requireNonNull(idleExpiresAt, "idleExpiresAt");
            Objects.requireNonNull(absoluteExpiresAt, "absoluteExpiresAt");
        }
    }

    /** The admission time is outside the accepted skew: nothing changed. */
    record Rejected() implements ExtendSessionResult { }

    /** No live session behind that lookup (expired, ended or never existed). */
    record Gone() implements ExtendSessionResult { }

    /** Another writer moved the session every time we tried; the BFF decides whether to retry. */
    record Conflict() implements ExtendSessionResult { }

    record Unavailable() implements ExtendSessionResult { }
}
