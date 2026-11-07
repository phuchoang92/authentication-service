package com.vpbank.dcp.auth.application.port.out.model;

import java.time.Instant;
import java.util.regex.Pattern;
import lombok.NonNull;

/**
 * What kind of transaction a flow keeps in the cache: a purpose code, which becomes part of the key so flows
 * never read each other's records, and the payload type the store must decode. A flow declares one as a
 * constant and opens its transactions from it; the store knows nothing else about the flow.
 */
public record TransactionKind<P>(@NonNull String purpose, @NonNull Class<P> payloadType) {
    private static final Pattern PURPOSE = Pattern.compile("[a-z0-9-]{1,32}");

    public TransactionKind {
        if (!PURPOSE.matcher(purpose).matches()) {
            throw new IllegalArgumentException("A purpose is 1-32 lower-case letters, digits or dashes");
        }
    }

    /** A transaction of this kind that does not exist in the store yet (version 0), kept until {@code expiresAt}. */
    public CacheTransaction<P> open(String id, Instant expiresAt, P payload) {
        return new CacheTransaction<>(this, id, expiresAt, 0, payload);
    }
}
