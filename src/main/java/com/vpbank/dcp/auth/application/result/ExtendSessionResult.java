package com.vpbank.dcp.auth.application.result;

import java.time.Instant;
import lombok.NonNull;

public sealed interface ExtendSessionResult {
    record Extended(@NonNull Instant idleExpiresAt, @NonNull Instant absoluteExpiresAt) implements ExtendSessionResult {
    }

    /** The admission time is outside the accepted skew: nothing changed. */
    record Rejected() implements ExtendSessionResult { }

    /** No live session behind that lookup (expired, ended or never existed). */
    record Gone() implements ExtendSessionResult { }

    /** Another writer moved the session every time we tried; the BFF decides whether to retry. */
    record Conflict() implements ExtendSessionResult { }

    record Unavailable() implements ExtendSessionResult { }
}
