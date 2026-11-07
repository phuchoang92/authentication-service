package com.vpbank.dcp.auth.application.port.out.model;

import java.time.Instant;
import java.util.regex.Pattern;
import lombok.NonNull;

/**
 * One transaction in the cache, as the store keeps it: its kind, the ID the flow chose, when the store forgets
 * it, the compare-and-set version, and the flow's own payload. The store never looks inside the payload; every
 * business step, attempt count or state lives there. {@code version} counts the saved changes, so no two states
 * of a transaction are ever equal; a save or a removal succeeds only while the store still holds this one.
 *
 * <p>A new transaction comes from its kind ({@link TransactionKind#open}). The ID is the flow's choice: a device address such as {@code MOBILE:90359:tablet-2} for "one transaction
 * per device", or a UUID for independent transactions.
 */
public record CacheTransaction<P>(@NonNull TransactionKind<P> kind,
                                  @NonNull String id,
                                  @NonNull Instant expiresAt,
                                  long version,
                                  @NonNull P payload) {
    private static final Pattern ID = Pattern.compile("[A-Za-z0-9._:-]{1,200}");

    public CacheTransaction {
        if (!ID.matcher(id).matches()) {
            throw new IllegalArgumentException("A transaction ID is 1-200 letters, digits, '.', '_', ':' or '-'");
        }
        if (version < 0) {
            throw new IllegalArgumentException("Version cannot be negative");
        }
        if (!kind.payloadType().isInstance(payload)) {
            throw new IllegalArgumentException("Payload is not a " + kind.payloadType().getSimpleName());
        }
    }

    public boolean isOpen(Instant now) {
        return now.isBefore(expiresAt);
    }

    /** The transaction after the flow moved it on: the changed payload, one version later, the same deadline. */
    public CacheTransaction<P> next(P changedPayload) {
        return new CacheTransaction<>(kind, id, expiresAt, version + 1, changedPayload);
    }

    /** The payload may hold keys or challenges; only the address and the revision are printed. */
    @Override
    public String toString() {
        return "CacheTransaction[purpose=" + kind.purpose() + ", id=" + id + ", version=" + version + ", redacted]";
    }
}
