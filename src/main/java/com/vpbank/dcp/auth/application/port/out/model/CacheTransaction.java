package com.vpbank.dcp.auth.application.port.out.model;

import java.time.Instant;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * One transaction in the cache, as the store keeps it: its kind, the ID the flow chose, when the store forgets
 * it, the compare-and-set version, and the flow's own payload. The store never looks inside the payload; every
 * business step, attempt count or state lives there. {@code version} is the revision the store must still see
 * when it saves or removes the transaction; each saved change increments it in the store.
 *
 * <p>The ID is the flow's choice: a device address such as {@code MOBILE:90359:tablet-2} for "one transaction
 * per device", or a UUID for independent transactions.
 */
public record CacheTransaction<P>(TransactionKind<P> kind, String id, Instant expiresAt, long version, P payload) {
    private static final Pattern ID = Pattern.compile("[A-Za-z0-9._:-]{1,200}");

    public CacheTransaction {
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(expiresAt, "expiresAt");
        Objects.requireNonNull(payload, "payload");
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

    /** A transaction that does not exist in the store yet: version 0. */
    public static <P> CacheTransaction<P> open(TransactionKind<P> kind, String id, Instant expiresAt, P payload) {
        return new CacheTransaction<>(kind, id, expiresAt, 0, payload);
    }

    public boolean isOpen(Instant now) {
        return now.isBefore(expiresAt);
    }

    /** The same transaction with the payload the flow moved on; saved with {@code saveIfCurrent}. */
    public CacheTransaction<P> withPayload(P changed) {
        return new CacheTransaction<>(kind, id, expiresAt, version, changed);
    }

    public CacheTransaction<P> withVersion(long storedVersion) {
        return new CacheTransaction<>(kind, id, expiresAt, storedVersion, payload);
    }

    /** The payload may hold keys or challenges; only the address and the revision are printed. */
    @Override
    public String toString() {
        return "CacheTransaction[purpose=" + kind.purpose() + ", id=" + id + ", version=" + version + ", redacted]";
    }
}
