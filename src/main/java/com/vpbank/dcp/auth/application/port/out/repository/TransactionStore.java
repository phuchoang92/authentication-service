package com.vpbank.dcp.auth.application.port.out.repository;

import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.port.out.model.CacheTransaction;
import com.vpbank.dcp.auth.application.port.out.model.TransactionKind;
import java.util.Optional;

/**
 * Transactions in flight, in the cache (Valkey): any flow, any payload. One record per kind and ID, gone at its
 * {@code expiresAt}. Every write is compare-and-set: it succeeds only while the store still holds exactly the
 * transaction the caller read (each save moves {@code version} on, so an earlier state never comes back). Two
 * callers moving the same transaction cannot both win, and a removal can serve as a one-shot. The store carries no business rule: it
 * does not know what a step, an attempt or a deadline means; the flow decides that on the payload. Every method
 * throws {@link RepositoryUnavailableException} when the store cannot answer; an uncertain write is reported as
 * unavailable, never as success.
 */
public interface TransactionStore {

    /** Stores a new transaction (version 0). False when that kind and ID already exist: nothing is overwritten. */
    <P> boolean createIfAbsent(CacheTransaction<P> fresh);

    <P> Optional<CacheTransaction<P>> find(TransactionKind<P> kind, String id);

    /**
     * Replaces the payload only if the store still holds {@code current}; returns the stored transaction
     * (version + 1). Empty = stale or gone.
     */
    <P> Optional<CacheTransaction<P>> saveIfCurrent(CacheTransaction<P> current, P changedPayload);

    /**
     * Removes the transaction only if the store still holds {@code current}. Of two racing callers exactly one
     * gets true.
     */
    <P> boolean deleteIfCurrent(CacheTransaction<P> current);
}
