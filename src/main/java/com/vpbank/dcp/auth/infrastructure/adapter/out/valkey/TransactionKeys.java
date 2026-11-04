package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

import com.vpbank.dcp.auth.application.port.out.model.CacheTransaction;
import com.vpbank.dcp.auth.application.port.out.model.TransactionKind;
import java.util.Objects;

/**
 * Key factory for cache transactions: {@code <namespace><purpose>:<id>}, default namespace {@code tx:v1:}. The
 * purpose and the ID are validated by {@link TransactionKind} and {@link CacheTransaction}; the namespace lets
 * two services share one Valkey without sharing keys. No key material, no I/O, no clock, no TTL decisions here.
 */
public final class TransactionKeys {
    static final String DEFAULT_NAMESPACE = "tx:v1:";

    private final String namespace;

    public TransactionKeys() {
        this(DEFAULT_NAMESPACE);
    }

    public TransactionKeys(String namespace) {
        this.namespace = Objects.requireNonNull(namespace, "namespace");
        if (namespace.isBlank() || !namespace.endsWith(":")) {
            throw new IllegalArgumentException("A key namespace ends with ':'");
        }
    }

    public String forTransaction(TransactionKind<?> kind, String id) {
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(id, "id");
        return namespace + kind.purpose() + ":" + id;
    }

    public String forTransaction(CacheTransaction<?> transaction) {
        return forTransaction(transaction.kind(), transaction.id());
    }
}
