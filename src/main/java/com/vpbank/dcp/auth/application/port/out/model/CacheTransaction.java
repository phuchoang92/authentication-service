package com.vpbank.dcp.auth.application.port.out.model;

import java.time.Instant;
import java.util.regex.Pattern;
import lombok.NonNull;

/**
 * One transaction in the cache, as the store keeps it: its kind, the ID the flow chose, when the store forgets
 * it, and the flow's own payload. The store never looks inside the payload; every business step, attempt count
 * or state lives there. A save or a removal succeeds only while the store still holds exactly this transaction.
 *
 * <p>There is no version counter: the store compares the whole record. A flow therefore moves its payload
 * forward only (a counter goes up, a state moves on), so that an earlier state never comes back and two
 * different moments of a transaction are never equal.
 *
 * <p>A new transaction comes from its kind ({@link TransactionKind#open}). The ID is the flow's choice: a device
 * address such as {@code MOBILE:90359:tablet-2} for "one transaction per device", or a UUID for independent
 * transactions.
 */
public record CacheTransaction<P>(@NonNull TransactionKind<P> kind,
                                  @NonNull String id,
                                  @NonNull Instant expiresAt,
                                  @NonNull P payload) {
    private static final Pattern ID = Pattern.compile("[A-Za-z0-9._:-]{1,200}");

    public CacheTransaction {
        if (!ID.matcher(id).matches()) {
            throw new IllegalArgumentException("A transaction ID is 1-200 letters, digits, '.', '_', ':' or '-'");
        }
        if (!kind.payloadType().isInstance(payload)) {
            throw new IllegalArgumentException("Payload is not a " + kind.payloadType().getSimpleName());
        }
    }

    public boolean isOpen(Instant now) {
        return now.isBefore(expiresAt);
    }

    /** The transaction after the flow moved it on: the changed payload under the same address and deadline. */
    public CacheTransaction<P> next(P changedPayload) {
        return new CacheTransaction<>(kind, id, expiresAt, changedPayload);
    }

    /** The payload may hold keys or challenges; only the address is printed. */
    @Override
    public String toString() {
        return "CacheTransaction[purpose=" + kind.purpose() + ", id=" + id + ", redacted]";
    }
}
