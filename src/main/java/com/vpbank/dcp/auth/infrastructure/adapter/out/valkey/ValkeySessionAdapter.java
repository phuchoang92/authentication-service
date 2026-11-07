package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.port.out.model.SessionLookup;
import com.vpbank.dcp.auth.application.port.out.model.StoredSession;
import com.vpbank.dcp.auth.application.port.out.repository.SessionStore;
import com.vpbank.dcp.auth.domain.model.OpaqueToken;
import com.vpbank.dcp.auth.domain.model.Session;
import java.util.Optional;
import java.util.function.Supplier;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataAccessException;

/**
 * {@link SessionStore} on Valkey (doc 22, decided 2026-11-07): one JSON STRING per session under
 * {@link SessionKeys}, forgotten by the server at the idle deadline. Every call is one command
 * ({@link ValkeyRecordCommands}); a save names the text of the record the caller read, and Valkey applies it only
 * while the key still holds that text. The BFF reads the same record, read-only. Spring exceptions never leave
 * this class.
 */
@RequiredArgsConstructor
public final class ValkeySessionAdapter implements SessionStore {
    @NonNull private final ValkeyRecordCommands recordCommands;
    @NonNull private final SessionKeys sessionKeys;
    @NonNull private final SessionJsonCodec sessionJsonCodec;

    @Override
    public void create(Session session, OpaqueToken token) {
        if (!token.sessionId().equals(session.id()) || token.channel() != session.channel()) {
            throw new IllegalArgumentException("Token and session do not name the same session");
        }
        SessionLookup lookup = sessionKeys.lookupOf(token);
        SessionRecord record = new SessionRecord(session, SessionSecretDigest.of(token.secret()));

        boolean created = translate(() -> recordCommands.createIfAbsent(valkeyRecordOf(lookup, record)));
        if (!created) {
            // Session IDs are random UUIDs: a key in use is a programming error, never something to overwrite.
            throw new IllegalStateException("A session with this ID already exists");
        }
    }

    /** By token: the stored digest must be that of the presented secret (constant time); otherwise "no session". */
    @Override
    public Optional<StoredSession> findByToken(OpaqueToken token) {
        SessionLookup lookup = sessionKeys.lookupOf(token);
        Optional<SessionRecord> record = findRecord(lookup);
        if (record.isEmpty() || !SessionSecretDigest.matches(record.get().secretDigest(), token.secret())) {
            return Optional.empty();
        }
        return Optional.of(storedSessionOf(lookup, record.get()));
    }

    @Override
    public Optional<StoredSession> findByLookup(SessionLookup lookup) {
        return findRecord(lookup).map(record -> storedSessionOf(lookup, record));
    }

    @Override
    public Optional<Session> saveIfCurrent(StoredSession current, Session changed) {
        Session next = changed.withSessionVersion(current.session().sessionVersion() + 1);
        SessionRecord currentRecord = new SessionRecord(current.session(), current.secretDigest());
        SessionRecord nextRecord = new SessionRecord(next, current.secretDigest());
        ValkeyRecord expected = valkeyRecordOf(current.lookup(), currentRecord);
        ValkeyRecord replacement = valkeyRecordOf(current.lookup(), nextRecord);

        boolean replaced = translate(() -> recordCommands.replaceIfUnchanged(expected, replacement));
        if (!replaced) {
            return Optional.empty();
        }
        return Optional.of(next);
    }

    /** One DEL; Valkey answers whether the key went, so a race has exactly one winner. */
    @Override
    public boolean delete(SessionLookup lookup) {
        String key = sessionKeys.forLookup(lookup);
        return translate(() -> recordCommands.delete(key));
    }

    private Optional<SessionRecord> findRecord(SessionLookup lookup) {
        String key = sessionKeys.forLookup(lookup);
        Optional<String> storedText = translate(() -> recordCommands.read(key));
        return storedText.flatMap(sessionJsonCodec::decode);
    }

    private ValkeyRecord valkeyRecordOf(SessionLookup lookup, SessionRecord record) {
        return new ValkeyRecord(
                sessionKeys.forLookup(lookup),
                sessionJsonCodec.encode(record),
                record.session().idleExpiresAt());
    }

    private static StoredSession storedSessionOf(SessionLookup lookup, SessionRecord record) {
        return new StoredSession(lookup, record.session(), record.secretDigest());
    }

    private static <T> T translate(Supplier<T> storeCall) {
        try {
            return storeCall.get();
        } catch (DataAccessException failure) {
            throw new RepositoryUnavailableException(failure);
        }
    }
}
