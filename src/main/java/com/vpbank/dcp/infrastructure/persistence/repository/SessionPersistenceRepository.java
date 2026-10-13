package com.vpbank.dcp.infrastructure.persistence.repository;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.port.out.session.SessionActivationFacts;
import com.vpbank.dcp.core.port.out.session.PreparedSession;
import com.vpbank.dcp.infrastructure.persistence.projection.PreparedSessionView;
import jakarta.persistence.EntityManager;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/** Intent and encrypted delivery SQL; the calling adapter owns their transaction. */
public final class SessionPersistenceRepository {
    private final EntityManager sql;

    public SessionPersistenceRepository(EntityManager sql) {
        this.sql = Objects.requireNonNull(sql);
    }

    public boolean hasIntent(UUID operationId) {
        List<?> rows = sql.createNativeQuery(SessionSql.EXISTING_INTENT)
                .setParameter("operationId", operationId.toString()).getResultList();
        if (rows.size() > 1) {
            throw new InvalidSessionPersistenceException();
        }
        return !rows.isEmpty();
    }

    public void insertIntent(PreparedSession candidate) {
        SessionActivationFacts facts = candidate.facts();
        int intent = sql.createNativeQuery(SessionSql.INSERT_INTENT)
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
    }

    public void insertEscrow(PreparedSession candidate, byte[] protectedResult,
                             Digest32 resultDigest) {
        SessionActivationFacts facts = candidate.facts();
        int escrow = sql.createNativeQuery(SessionSql.INSERT_ESCROW)
                .setParameter("escrowId", UUID.randomUUID().toString())
                .setParameter("intentId", candidate.intentId().toString())
                .setParameter("operationId", facts.operationId().toString())
                .setParameter("protectedResult", protectedResult)
                .setParameter("resultDigest", resultDigest.bytes())
                .setParameter("deliveryDeadline", local(candidate.deliveryDeadline()))
                .executeUpdate();
        exactlyOne(escrow);
    }

    public Optional<PreparedSessionView> prepared(UUID operationId) {
        List<?> rows = sql.createNativeQuery(SessionSql.PREPARED)
                .setParameter("operationId", operationId.toString()).getResultList();
        if (rows.isEmpty()) {
            return Optional.empty();
        }
        if (rows.size() != 1) {
            throw new InvalidSessionPersistenceException();
        }
        Object[] row = (Object[]) rows.getFirst();
        return Optional.of(new PreparedSessionView(uuid(row[0]), uuid(row[1]),
                uuid(row[2]), (String) row[3], (byte[]) row[4], (byte[]) row[5],
                utc(row[6]), utc(row[7]), utc(row[8]), (byte[]) row[9],
                (byte[]) row[10], number(row[11]), number(row[12]), number(row[13]),
                (byte[]) row[14], uuid(row[15]), uuid(row[16])));
    }

    public Optional<String> intentState(UUID operationId, UUID intentId) {
        List<?> states = sql.createNativeQuery(SessionSql.COMPLETED)
                .setParameter("intentId", intentId.toString())
                .setParameter("operationId", operationId.toString()).getResultList();
        return states.size() == 1 ? Optional.of((String) states.getFirst()) : Optional.empty();
    }

    public void markIntentApplied(UUID operationId, UUID intentId) {
        exactlyOne(sql.createNativeQuery(SessionSql.MARK_INTENT_APPLIED)
                .setParameter("intentId", intentId.toString())
                .setParameter("operationId", operationId.toString()).executeUpdate());
    }

    private void exactlyOne(int rows) {
        if (rows != 1) {
            throw new InvalidSessionPersistenceException();
        }
    }

    private UUID uuid(Object value) { return UUID.fromString((String) value); }
    private long number(Object value) { return ((Number) value).longValue(); }
    private Instant utc(Object value) { return ((LocalDateTime) value).toInstant(ZoneOffset.UTC); }
    private LocalDateTime local(Instant value) { return LocalDateTime.ofInstant(value, ZoneOffset.UTC); }
}
