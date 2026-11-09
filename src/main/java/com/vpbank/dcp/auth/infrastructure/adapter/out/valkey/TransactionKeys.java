package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

import com.vpbank.dcp.auth.application.port.out.model.CacheTransaction;
import com.vpbank.dcp.auth.application.port.out.model.TransactionKind;
import lombok.NonNull;

/**
 * Key factory for cache transactions: {@code <namespace><purpose>:<id>}, default namespace {@code tx:v4:} (v2: the
 * record became one JSON STRING; v3: its {@code version} counter went; v4: the enrollment payload keeps the answers
 * of init and verify). The purpose and the ID are validated by
 * {@link TransactionKind} and {@link CacheTransaction}; the namespace lets two services share one Valkey without
 * sharing keys. No key material, no I/O, no clock, no TTL decisions here.
 */
public final class TransactionKeys {
    static final String DEFAULT_NAMESPACE = "tx:v4:";

    private final String namespace;

    public TransactionKeys() {
        this(DEFAULT_NAMESPACE);
    }

    public TransactionKeys(@NonNull String namespace) {
        this.namespace = namespace;
        if (namespace.isBlank() || !namespace.endsWith(":")) {
            throw new IllegalArgumentException("A key namespace ends with ':'");
        }
    }

    public String forTransaction(@NonNull TransactionKind<?> kind, @NonNull String id) {
        return namespace + kind.purpose() + ":" + id;
    }

    public String forTransaction(CacheTransaction<?> transaction) {
        return forTransaction(transaction.kind(), transaction.id());
    }
}
