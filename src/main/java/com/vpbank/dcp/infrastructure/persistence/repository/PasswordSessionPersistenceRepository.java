package com.vpbank.dcp.infrastructure.persistence.repository;

import com.vpbank.dcp.core.port.out.session.SessionActivationFacts;
import com.vpbank.dcp.infrastructure.persistence.projection.PasswordSessionFactsView;
import jakarta.persistence.EntityManager;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import org.hibernate.query.NativeQuery;

/** Parameter binding and row mapping only; transaction order is owned by its adapter. */
public final class PasswordSessionPersistenceRepository {
    private final EntityManager sql;

    public PasswordSessionPersistenceRepository(EntityManager sql) {
        this.sql = Objects.requireNonNull(sql);
    }

    public Optional<PasswordSessionFactsView> currentFacts(UUID operationId, UUID subjectId) {
        List<?> rows = sql.createNativeQuery(PasswordSessionSql.CURRENT_FACTS)
                .unwrap(NativeQuery.class)
                .addScalar("BIN_TO_UUID(o.id)", String.class)
                .addScalar("BIN_TO_UUID(j.id)", String.class)
                .addScalar("BIN_TO_UUID(s.id)", String.class)
                .addScalar("app_id", String.class)
                .addScalar("BIN_TO_UUID(b.id)", String.class)
                .addScalar("request_jkt", byte[].class)
                .addScalar("CAST(j.request_public_jwk AS CHAR)", String.class)
                .addScalar("CAST(j.response_public_jwk AS CHAR)", String.class)
                .addScalar("device_proof_jkt", byte[].class)
                .addScalar("customer_security_version", Long.class)
                .addScalar("credential_security_version", Long.class)
                .addScalar("device_security_version", Long.class)
                .addScalar("customer_status_version", Long.class)
                // Freshness must use the stored instant, never a JVM-local wall clock.
                .addScalar("customer_status_checked_at", Instant.class)
                .addScalar("platform_assurance", String.class)
                .addScalar("biometric_capable", Integer.class)
                .setParameter("operationId", operationId.toString())
                .setParameter("subjectId", subjectId.toString()).getResultList();
        if (rows.isEmpty()) {
            return Optional.empty();
        }
        if (rows.size() != 1) {
            throw new InvalidSessionPersistenceException();
        }
        Object[] row = (Object[]) rows.getFirst();
        return Optional.of(new PasswordSessionFactsView(uuid(row[0]), uuid(row[1]), uuid(row[2]),
                (String) row[3], uuid(row[4]), (byte[]) row[5], (String) row[6],
                (String) row[7], (byte[]) row[8], number(row[9]), number(row[10]),
                number(row[11]), number(row[12]), (Instant) row[13],
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

    public void finalizeJourney(SessionActivationFacts facts) {
        int journey = sql.createNativeQuery(PasswordSessionSql.FINALIZING_JOURNEY)
                .setParameter("journeyId", facts.journeyId().toString())
                .setParameter("bindingId", facts.bindingId().toString()).executeUpdate();
        exactlyOne(journey);
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
            throw new InvalidSessionPersistenceException();
        }
    }

    private void exactlyOne(int rows) {
        if (rows != 1) {
            throw new InvalidSessionPersistenceException();
        }
    }

    private UUID uuid(Object value) { return UUID.fromString((String) value); }
    private long number(Object value) { return ((Number) value).longValue(); }
}
