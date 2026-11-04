package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.port.out.model.CacheTransaction;
import com.vpbank.dcp.auth.application.port.out.model.TransactionKind;
import com.vpbank.dcp.auth.application.port.out.repository.TransactionStore;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/** Test double with the store's contract: one record per kind and ID, compare-and-set on version, version + 1 per save. */
final class InMemoryTransactionStore implements TransactionStore {
    record Key(String purpose, String id) {
    }

    final Map<Key, CacheTransaction<?>> rows = new HashMap<>();
    boolean unavailable;

    @Override
    public <P> boolean createIfAbsent(CacheTransaction<P> fresh) {
        check();
        return rows.putIfAbsent(keyOf(fresh), fresh) == null;
    }

    @Override
    @SuppressWarnings("unchecked")
    public <P> Optional<CacheTransaction<P>> find(TransactionKind<P> kind, String id) {
        check();
        return Optional.ofNullable((CacheTransaction<P>) rows.get(new Key(kind.purpose(), id)));
    }

    @Override
    public <P> Optional<CacheTransaction<P>> saveIfCurrent(CacheTransaction<P> changed) {
        check();
        CacheTransaction<?> stored = rows.get(keyOf(changed));
        if (stored == null || stored.version() != changed.version()) {
            return Optional.empty();
        }
        CacheTransaction<P> saved = changed.withVersion(changed.version() + 1);
        rows.put(keyOf(changed), saved);
        return Optional.of(saved);
    }

    @Override
    public <P> boolean deleteIfCurrent(CacheTransaction<P> current) {
        check();
        CacheTransaction<?> stored = rows.get(keyOf(current));
        if (stored == null || stored.version() != current.version()) {
            return false;
        }
        rows.remove(keyOf(current));
        return true;
    }

    @SuppressWarnings("unchecked")
    <P> CacheTransaction<P> only() {
        return (CacheTransaction<P>) rows.values().iterator().next();
    }

    private static Key keyOf(CacheTransaction<?> transaction) {
        return new Key(transaction.kind().purpose(), transaction.id());
    }

    private void check() {
        if (unavailable) {
            throw new RepositoryUnavailableException(new RuntimeException("down"));
        }
    }
}
