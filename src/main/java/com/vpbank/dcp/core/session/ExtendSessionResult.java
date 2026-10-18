package com.vpbank.dcp.core.session;

import com.vpbank.dcp.core.domain.session.SessionDeadlines;

import java.util.Objects;

public sealed interface ExtendSessionResult {

    /** The idle deadline is now {@code deadlines.idleExpiresAt()} (it may not have moved). */
    record Extended(SessionDeadlines deadlines) implements ExtendSessionResult {
        public Extended {
            Objects.requireNonNull(deadlines, "deadlines");
        }
    }

    /** Nothing was written; the BFF must not forward the App request. */
    record NotExtended(Reason reason) implements ExtendSessionResult {
        public NotExtended {
            Objects.requireNonNull(reason, "reason");
        }
    }

    enum Reason {
        /** Route not counted as activity, or {@code admittedAt} outside the allowed window. */
        INVALID_REQUEST,
        /** No ACTIVE session with this ID, or a deadline has passed. */
        GONE,
        /** Wrong request key or generation, or other writes kept winning. */
        CONFLICT,
        /** Valkey did not answer, or it is unknown whether the write applied. */
        UNAVAILABLE
    }
}
