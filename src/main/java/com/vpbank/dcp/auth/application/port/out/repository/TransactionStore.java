package com.vpbank.dcp.auth.application.port.out.repository;

import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.port.out.model.CacheTransaction;
import com.vpbank.dcp.auth.application.port.out.model.TransactionKind;
import java.util.Optional;

/**
 * Transactions in flight, in the cache (Valkey): any flow, any payload. One record per kind and ID, gone at its
 * {@code expiresAt}. Every write is compare-and-set on {@code version}, so two callers moving the same
 * transaction cannot both win and a removal can serve as a one-shot. The store carries no business rule: it
 * does not know what a step, an attempt or a deadline means; the flow decides that on the payload. Every method
 * throws {@link RepositoryUnavailableException} when the store cannot answer; an uncertain write is reported as
 * unavailable, never as success.
 */
public interface TransactionStore {

    /** Stores a new transaction (version 0). False when that kind and ID already exist: nothing is overwritten. */
    <P> boolean createIfAbsent(CacheTransaction<P> fresh);

    <P> Optional<CacheTransaction<P>> find(TransactionKind<P> kind, String id);

    /**
     * Saves a changed transaction only if the stored version still equals {@code changed.version()}; returns the
     * stored transaction (version + 1). Empty = stale or gone.
     */
    <P> Optional<CacheTransaction<P>> saveIfCurrent(CacheTransaction<P> changed);

    /**
     * Removes the transaction only if the stored version still equals {@code current.version()}. Of two racing
     * callers exactly one gets true.
     */
    <P> boolean deleteIfCurrent(CacheTransaction<P> current);
}
