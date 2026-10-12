package com.vpbank.dcp.infrastructure.persistence.repository;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.port.out.session.PasswordSessionFacts;
import com.vpbank.dcp.core.port.out.session.PreparedPasswordSession;
import com.vpbank.dcp.infrastructure.persistence.projection.PasswordSessionFactsView;
import com.vpbank.dcp.infrastructure.persistence.projection.PreparedPasswordSessionView;
import jakarta.persistence.EntityManager;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/** Parameter binding and row mapping only; transaction order is owned by its adapter. */
public final class PasswordSessionPersistenceRepository {
    private final EntityManager sql;

    public PasswordSessionPersistenceRepository(EntityManager sql) {
        this.sql = Objects.requireNonNull(sql);
    }

    public Optional<PasswordSessionFactsView> currentFacts(UUID operationId, UUID subjectId) {
        List<?> rows = sql.createNativeQuery(PasswordSessionSql.CURRENT_FACTS)
                .setParameter("operationId", operationId.toString())
                .setParameter("subjectId", subjectId.toString()).getResultList();
        if (rows.isEmpty()) {
            return Optional.empty();
        }
        if (rows.size() != 1) {
            throw new InvalidPasswordSessionPersistenceException();
        }
        Object[] row = (Object[]) rows.getFirst();
        return Optional.of(new PasswordSessionFactsView(uuid(row[0]), uuid(row[1]), uuid(row[2]),
                (String) row[3], uuid(row[4]), (byte[]) row[5], (String) row[6],
                (String) row[7], (byte[]) row[8], number(row[9]), number(row[10]),
                number(row[11]), number(row[12]), utc(row[13]),
                (String) row[14], ((Number) row[15]).intValue() == 1));
    }

    public UUID operationSubject(UUID operationId) {
        List<?> rows = sql.createNativeQuery(PasswordSessionSql.OPERATION_SUBJECT)
                .setParameter("operationId", operationId.toString()).getResultList();
        return rows.size() == 1 && rows.getFirst() != null ? uuid(rows.getFirst()) : null;
    }

    public void lockSubject(UUID subjectId) {
        requiredLock(PasswordSessionSql.LOCK_SUBJECT, "subjectId", subjectId);
    }

    public void lockSubjectApp(UUID subjectId, String appId) {
        requiredLock(PasswordSessionSql.LOCK_SUBJECT_APP, "subjectId", subjectId, "appId", appId);
    }

    public void lockBinding(UUID bindingId, UUID subjectId, String appId) {
        requiredLock(PasswordSessionSql.LOCK_BINDING, "bindingId", bindingId,
                "subjectId", subjectId, "appId", appId);
    }

    public void lockJourney(UUID journeyId) {
        requiredLock(PasswordSessionSql.LOCK_JOURNEY, "journeyId", journeyId);
    }

    public void lockOperation(UUID operationId) {
        requiredLock(PasswordSessionSql.LOCK_OPERATION, "operationId", operationId);
    }

    public boolean hasIntent(UUID operationId) {
        List<?> rows = sql.createNativeQuery(PasswordSessionSql.EXISTING_INTENT)
                .setParameter("operationId", operationId.toString()).getResultList();
        if (rows.size() > 1) {
            throw new InvalidPasswordSessionPersistenceException();
        }
        return !rows.isEmpty();
    }

    public void finalizeJourney(PasswordSessionFacts facts) {
        int journey = sql.createNativeQuery(PasswordSessionSql.FINALIZING_JOURNEY)
                .setParameter("journeyId", facts.journeyId().toString())
                .setParameter("bindingId", facts.bindingId().toString()).executeUpdate();
        exactlyOne(journey);
    }

    public void insertIntent(PreparedPasswordSession candidate) {
        PasswordSessionFacts facts = candidate.facts();
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
    }

    public void insertEscrow(PreparedPasswordSession candidate, byte[] protectedResult,
                             Digest32 resultDigest) {
        PasswordSessionFacts facts = candidate.facts();
        int escrow = sql.createNativeQuery(PasswordSessionSql.INSERT_ESCROW)
                .setParameter("escrowId", UUID.randomUUID().toString())
                .setParameter("intentId", candidate.intentId().toString())
                .setParameter("operationId", facts.operationId().toString())
                .setParameter("protectedResult", protectedResult)
                .setParameter("resultDigest", resultDigest.bytes())
                .setParameter("deliveryDeadline", local(candidate.deliveryDeadline()))
                .executeUpdate();
        exactlyOne(escrow);
    }

    public Optional<PreparedPasswordSessionView> prepared(UUID operationId) {
        List<?> rows = sql.createNativeQuery(PasswordSessionSql.PREPARED)
                .setParameter("operationId", operationId.toString()).getResultList();
        if (rows.isEmpty()) {
            return Optional.empty();
        }
        if (rows.size() != 1) {
            throw new InvalidPasswordSessionPersistenceException();
        }
        Object[] row = (Object[]) rows.getFirst();
        return Optional.of(new PreparedPasswordSessionView(uuid(row[0]), uuid(row[1]),
                uuid(row[2]), (String) row[3], (byte[]) row[4], (byte[]) row[5],
                utc(row[6]), utc(row[7]), utc(row[8]), (byte[]) row[9],
                (byte[]) row[10], number(row[11]), number(row[12]), number(row[13]),
                (byte[]) row[14], uuid(row[15]), uuid(row[16])));
    }

    public Optional<String> intentState(UUID operationId, UUID intentId) {
        List<?> states = sql.createNativeQuery(PasswordSessionSql.COMPLETED)
                .setParameter("intentId", intentId.toString())
                .setParameter("operationId", operationId.toString()).getResultList();
        return states.size() == 1 ? Optional.of((String) states.getFirst()) : Optional.empty();
    }

    public void markIntentApplied(UUID operationId, UUID intentId) {
        exactlyOne(sql.createNativeQuery(PasswordSessionSql.MARK_INTENT_APPLIED)
                .setParameter("intentId", intentId.toString())
                .setParameter("operationId", operationId.toString()).executeUpdate());
    }

    public void completeJourney(UUID journeyId) {
        exactlyOne(sql.createNativeQuery(PasswordSessionSql.COMPLETE_JOURNEY)
                .setParameter("journeyId", journeyId.toString()).executeUpdate());
    }

    public void completeOperation(UUID operationId) {
        exactlyOne(sql.createNativeQuery(PasswordSessionSql.COMPLETE_OPERATION)
                .setParameter("operationId", operationId.toString()).executeUpdate());
    }

    private void requiredLock(String query, Object... parameters) {
        var statement = sql.createNativeQuery(query);
        for (int i = 0; i < parameters.length; i += 2) {
            Object value = parameters[i + 1];
            statement.setParameter((String) parameters[i], value instanceof UUID id ? id.toString() : value);
        }
        if (statement.getResultList().size() != 1) {
            throw new InvalidPasswordSessionPersistenceException();
        }
    }

    private void exactlyOne(int rows) {
        if (rows != 1) {
            throw new InvalidPasswordSessionPersistenceException();
        }
    }

    private UUID uuid(Object value) { return UUID.fromString((String) value); }
    private long number(Object value) { return ((Number) value).longValue(); }
    private Instant utc(Object value) { return ((LocalDateTime) value).toInstant(ZoneOffset.UTC); }
    private LocalDateTime local(Instant value) { return LocalDateTime.ofInstant(value, ZoneOffset.UTC); }
}
