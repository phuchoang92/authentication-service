package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.port.out.model.CacheTransaction;
import com.vpbank.dcp.auth.application.port.out.model.TransactionKind;
import com.vpbank.dcp.auth.application.port.out.repository.TransactionStore;
import java.util.Optional;
import java.util.function.Supplier;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataAccessException;

/**
 * {@link TransactionStore} on Valkey: one JSON STRING per transaction under {@link TransactionKeys}, forgotten by
 * the server at {@code expiresAt}. Every call is one command ({@link ValkeyRecordCommands}). A save or a removal
 * names the text of the transaction the caller read, and Valkey applies it only while the key still holds that
 * text; {@code version} makes every saved state a different text. Spring exceptions never leave this class.
 */
@RequiredArgsConstructor
public final class ValkeyTransactionAdapter implements TransactionStore {
    @NonNull private final ValkeyRecordCommands recordCommands;
    @NonNull private final TransactionKeys transactionKeys;
    @NonNull private final TransactionJsonCodec transactionJsonCodec;

    @Override
    public <P> boolean createIfAbsent(CacheTransaction<P> fresh) {
        if (fresh.version() != 0) {
            throw new IllegalArgumentException("A new transaction starts at version 0");
        }
        ValkeyRecord freshRecord = recordOf(fresh);
        return translate(() -> recordCommands.createIfAbsent(freshRecord));
    }

    @Override
    public <P> Optional<CacheTransaction<P>> find(TransactionKind<P> kind, String id) {
        String key = transactionKeys.forTransaction(kind, id);
        Optional<String> storedText = translate(() -> recordCommands.read(key));
        return storedText.flatMap(text -> transactionJsonCodec.decode(kind, id, text));
    }

    @Override
    public <P> Optional<CacheTransaction<P>> saveIfCurrent(CacheTransaction<P> current, P changedPayload) {
        CacheTransaction<P> next = current.next(changedPayload);
        ValkeyRecord currentRecord = recordOf(current);
        ValkeyRecord nextRecord = recordOf(next);

        boolean replaced = translate(() -> recordCommands.replaceIfUnchanged(currentRecord, nextRecord));
        if (!replaced) {
            return Optional.empty();
        }
        return Optional.of(next);
    }

    @Override
    public <P> boolean deleteIfCurrent(CacheTransaction<P> current) {
        ValkeyRecord currentRecord = recordOf(current);
        return translate(() -> recordCommands.deleteIfUnchanged(currentRecord));
    }

    private ValkeyRecord recordOf(CacheTransaction<?> transaction) {
        return new ValkeyRecord(
                transactionKeys.forTransaction(transaction),
                transactionJsonCodec.encode(transaction),
                transaction.expiresAt());
    }

    private static <T> T translate(Supplier<T> storeCall) {
        try {
            return storeCall.get();
        } catch (DataAccessException failure) {
            throw new RepositoryUnavailableException(failure);
        }
    }
}
