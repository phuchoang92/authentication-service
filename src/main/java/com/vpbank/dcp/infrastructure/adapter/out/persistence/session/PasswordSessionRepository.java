package com.vpbank.dcp.infrastructure.adapter.out.persistence.session;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.LookupKeyVersion;
import com.vpbank.dcp.core.domain.session.SessionDeadlines;
import com.vpbank.dcp.core.port.out.session.PasswordSessionFacts;
import com.vpbank.dcp.core.port.out.session.PreparedPasswordSession;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.Sha256Digests;
import jakarta.persistence.EntityManager;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import tools.jackson.databind.json.JsonMapper;

/** Parameter binding and row mapping only; transaction order is owned by its store. */
public final class PasswordSessionRepository {
    private final EntityManager sql;
    private final JsonMapper json;
    private final Duration customerMaxAge;
    private final Sha256Digests digests = new Sha256Digests();

    public PasswordSessionRepository(EntityManager sql, JsonMapper json,
                              Duration customerMaxAge) {
        this.sql = Objects.requireNonNull(sql);
        this.json = Objects.requireNonNull(json);
        this.customerMaxAge = Objects.requireNonNull(customerMaxAge);
        if (customerMaxAge.isZero() || customerMaxAge.isNegative()) {
            throw new InvalidPasswordSessionStoreException();
        }
    }

    Optional<PasswordSessionFacts> currentFacts(UUID operationId, UUID subjectId) {
        List<?> rows = sql.createNativeQuery(PasswordSessionSql.CURRENT_FACTS)
                .setParameter("operationId", operationId.toString())
                .setParameter("subjectId", subjectId.toString()).getResultList();
        if (rows.isEmpty()) {
            return Optional.empty();
        }
        if (rows.size() != 1) {
            throw new InvalidPasswordSessionStoreException();
        }
        Object[] row = (Object[]) rows.getFirst();
        return Optional.of(new PasswordSessionFacts(uuid(row[0]), uuid(row[1]), uuid(row[2]),
                (String) row[3], uuid(row[4]), digest(row[5]), (String) row[6],
                (String) row[7], digest(row[8]), number(row[9]), number(row[10]),
                number(row[11]), number(row[12]), utc(row[13]).plus(customerMaxAge),
                (String) row[14], ((Number) row[15]).intValue() == 1));
    }

    UUID operationSubject(UUID operationId) {
        List<?> rows = sql.createNativeQuery(PasswordSessionSql.OPERATION_SUBJECT)
                .setParameter("operationId", operationId.toString()).getResultList();
        return rows.size() == 1 && rows.getFirst() != null ? uuid(rows.getFirst()) : null;
    }

    void lock(PasswordSessionFacts facts) {
        requiredLock(PasswordSessionSql.LOCK_SUBJECT, "subjectId", facts.subjectId());
        requiredLock(PasswordSessionSql.LOCK_SUBJECT_APP, "subjectId", facts.subjectId(),
                "appId", facts.appId());
        requiredLock(PasswordSessionSql.LOCK_BINDING, "bindingId", facts.bindingId(),
                "subjectId", facts.subjectId(), "appId", facts.appId());
        requiredLock(PasswordSessionSql.LOCK_JOURNEY, "journeyId", facts.journeyId());
        requiredLock(PasswordSessionSql.LOCK_OPERATION, "operationId", facts.operationId());
    }

    boolean hasIntent(UUID operationId) {
        List<?> rows = sql.createNativeQuery(PasswordSessionSql.EXISTING_INTENT)
                .setParameter("operationId", operationId.toString()).getResultList();
        if (rows.size() > 1) {
            throw new InvalidPasswordSessionStoreException();
        }
        return !rows.isEmpty();
    }

    void insert(PreparedPasswordSession candidate) {
        PasswordSessionFacts facts = candidate.facts();
        int journey = sql.createNativeQuery(PasswordSessionSql.FINALIZING_JOURNEY)
                .setParameter("journeyId", facts.journeyId().toString())
                .setParameter("bindingId", facts.bindingId().toString()).executeUpdate();
        exactlyOne(journey);
        int intent = sql.createNativeQuery(PasswordSessionSql.INSERT_INTENT)
                .setParameter("intentId", candidate.intentId().toString())
                .setParameter("subjectId", facts.subjectId().toString())
                .setParameter("appId", facts.appId())
                .setParameter("journeyId", facts.journeyId().toString())
                .setParameter("operationId", facts.operationId().toString())
                .setParameter("bindingId", facts.bindingId().toString())
                .setParameter("requestJkt", facts.requestKey().bytes())
                .setParameter("generation", candidate.generation().toString())
                .setParameter("sessionId", candidate.sessionId().toString())
                .setParameter("lookupDigest", candidate.lookupDigest().bytes())
                .setParameter("lookupVersion", candidate.lookupVersion().value())
                .setParameter("customerVersion", facts.customerSecurityVersion())
                .setParameter("credentialVersion", facts.credentialSecurityVersion())
                .setParameter("deviceVersion", facts.deviceSecurityVersion())
                .setParameter("candidateDigest", candidate.candidateDigest().bytes())
                .setParameter("idleExpiry", local(candidate.deadlines().idleExpiresAt()))
                .setParameter("absoluteExpiry", local(candidate.deadlines().absoluteExpiresAt()))
                .executeUpdate();
        exactlyOne(intent);
        byte[] protectedResult = json.writeValueAsBytes(new EscrowedPasswordDelivery(
                candidate.tokenEnvelope(), candidate.receipt(), candidate.dpopNonce()));
        int escrow = sql.createNativeQuery(PasswordSessionSql.INSERT_ESCROW)
                .setParameter("escrowId", UUID.randomUUID().toString())
                .setParameter("intentId", candidate.intentId().toString())
                .setParameter("operationId", facts.operationId().toString())
                .setParameter("protectedResult", protectedResult)
                .setParameter("resultDigest", digests.sha256(protectedResult).bytes())
                .setParameter("deliveryDeadline", local(candidate.deliveryDeadline()))
                .executeUpdate();
        exactlyOne(escrow);
    }

    Optional<PreparedPasswordSession> prepared(UUID operationId, PasswordSessionFacts facts) {
        List<?> rows = sql.createNativeQuery(PasswordSessionSql.PREPARED)
                .setParameter("operationId", operationId.toString()).getResultList();
        if (rows.isEmpty() || facts == null) {
            return Optional.empty();
        }
        if (rows.size() != 1) {
            throw new InvalidPasswordSessionStoreException();
        }
        Object[] row = (Object[]) rows.getFirst();
        if (number(row[11]) != facts.customerSecurityVersion()
                || number(row[12]) != facts.credentialSecurityVersion()
                || number(row[13]) != facts.deviceSecurityVersion()
                || !Arrays.equals((byte[]) row[14], facts.requestKey().bytes())
                || !uuid(row[15]).equals(facts.bindingId())
                || !uuid(row[16]).equals(facts.subjectId())) {
            return Optional.empty();
        }
        byte[] protectedResult = (byte[]) row[9];
        if (protectedResult == null || !digests.sha256(protectedResult).equals(digest(row[10]))) {
            throw new InvalidPasswordSessionStoreException();
        }
        EscrowedPasswordDelivery envelope = json.readValue(protectedResult,
                EscrowedPasswordDelivery.class);
        return Optional.of(new PreparedPasswordSession(facts, uuid(row[0]), uuid(row[1]),
                uuid(row[2]), new LookupKeyVersion((String) row[3]), digest(row[4]),
                digest(row[5]), envelope.tokenEnvelope(), envelope.receipt(),
                envelope.dpopNonce(),
                new SessionDeadlines(utc(row[6]), utc(row[7])), utc(row[8])));
    }

    boolean markApplied(PreparedPasswordSession candidate) {
        UUID operationId = candidate.facts().operationId();
        List<?> states = sql.createNativeQuery(PasswordSessionSql.COMPLETED)
                .setParameter("intentId", candidate.intentId().toString())
                .setParameter("operationId", operationId.toString()).getResultList();
        if (states.size() != 1) {
            return false;
        }
        if ("COMPLETED".equals(states.getFirst())) {
            return true;
        }
        if (!"READY".equals(states.getFirst())) {
            return false;
        }
        exactlyOne(sql.createNativeQuery(PasswordSessionSql.MARK_INTENT_APPLIED)
                .setParameter("intentId", candidate.intentId().toString())
                .setParameter("operationId", operationId.toString()).executeUpdate());
        exactlyOne(sql.createNativeQuery(PasswordSessionSql.COMPLETE_JOURNEY)
                .setParameter("journeyId", candidate.facts().journeyId().toString()).executeUpdate());
        exactlyOne(sql.createNativeQuery(PasswordSessionSql.COMPLETE_OPERATION)
                .setParameter("operationId", operationId.toString()).executeUpdate());
        return true;
    }

    private void requiredLock(String query, Object... parameters) {
        var statement = sql.createNativeQuery(query);
        for (int i = 0; i < parameters.length; i += 2) {
            Object value = parameters[i + 1];
            statement.setParameter((String) parameters[i], value instanceof UUID id ? id.toString() : value);
        }
        if (statement.getResultList().size() != 1) {
            throw new InvalidPasswordSessionStoreException();
        }
    }

    private void exactlyOne(int rows) {
        if (rows != 1) {
            throw new InvalidPasswordSessionStoreException();
        }
    }

    private UUID uuid(Object value) { return UUID.fromString((String) value); }
    private Digest32 digest(Object value) { return Digest32.fromBytes((byte[]) value); }
    private long number(Object value) { return ((Number) value).longValue(); }
    private Instant utc(Object value) { return ((LocalDateTime) value).toInstant(ZoneOffset.UTC); }
    private LocalDateTime local(Instant value) { return LocalDateTime.ofInstant(value, ZoneOffset.UTC); }
}
