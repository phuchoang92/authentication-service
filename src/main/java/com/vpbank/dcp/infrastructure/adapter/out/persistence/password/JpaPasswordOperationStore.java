package com.vpbank.dcp.infrastructure.adapter.out.persistence.password;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.port.out.password.PasswordDispatchResult;
import com.vpbank.dcp.core.port.out.password.PasswordCredentialRecordResult;
import com.vpbank.dcp.core.port.out.password.PasswordOperationStore;
import com.vpbank.dcp.core.port.out.password.PasswordReservation;
import com.vpbank.dcp.core.port.out.password.PasswordReservationResult;
import jakarta.persistence.EntityManager;
import org.hibernate.exception.ConstraintViolationException;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.support.TransactionTemplate;

import java.sql.Timestamp;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * Commits reservation and dispatch claims separately; no provider call occurs here.
 */
@Repository
public class JpaPasswordOperationStore implements PasswordOperationStore {

    private final EntityManager entityManager;
    private final TransactionTemplate transactions;

    public JpaPasswordOperationStore(EntityManager entityManager,
                                     TransactionTemplate transactions) {
        this.entityManager = Objects.requireNonNull(entityManager, "entityManager");
        this.transactions = Objects.requireNonNull(transactions, "transactions");
    }

    @Override
    public PasswordReservationResult reserve(PasswordReservation reservation) {
        Objects.requireNonNull(reservation, "reservation");
        UUID journeyId = UUID.randomUUID();
        try {
            transactions.executeWithoutResult(status -> insert(reservation, journeyId));
            return new PasswordReservationResult.Created(journeyId);
        } catch (ConstraintViolationException duplicate) {
            if (duplicate.getSQLException().getErrorCode() != 1062) {
                throw duplicate;
            }
            return findExisting(reservation);
        }
    }

    @Override
    public PasswordDispatchResult claimDispatch(UUID operationId) {
        Objects.requireNonNull(operationId, "operationId");
        PasswordDispatchResult result = transactions.execute(status -> {
            int journeyUpdated = update(PasswordOperationSql.CLAIM_JOURNEY_FOR_DISPATCH, operationId);
            if (journeyUpdated == 0) {
                return dispatchNotClaimed(operationId);
            }
            int operationUpdated = update(PasswordOperationSql.CLAIM_DISPATCH, operationId);
            if (operationUpdated != 1) {
                status.setRollbackOnly();
                return PasswordDispatchResult.NOT_CLAIMABLE;
            }
            return PasswordDispatchResult.CLAIMED;
        });
        return Objects.requireNonNull(result, "result");
    }

    @Override
    public PasswordCredentialRecordResult recordRejection(UUID operationId) {
        Objects.requireNonNull(operationId, "operationId");
        PasswordCredentialRecordResult result = transactions.execute(status -> {
            int journeyUpdated = update(PasswordOperationSql.REJECT_JOURNEY, operationId);
            if (journeyUpdated == 0) {
                return recordedState(operationId, "REJECTED");
            }
            if (update(PasswordOperationSql.REJECT_OPERATION, operationId) != 1) {
                status.setRollbackOnly();
                return PasswordCredentialRecordResult.NOT_RECORDABLE;
            }
            return PasswordCredentialRecordResult.RECORDED;
        });
        return Objects.requireNonNull(result, "result");
    }

    @Override
    public PasswordCredentialRecordResult recordUncertain(UUID operationId) {
        Objects.requireNonNull(operationId, "operationId");
        PasswordCredentialRecordResult result = transactions.execute(status -> {
            int updated = update(PasswordOperationSql.RECORD_UNCERTAIN, operationId);
            return updated == 1 ? PasswordCredentialRecordResult.RECORDED
                    : recordedState(operationId, "UNCERTAIN");
        });
        return Objects.requireNonNull(result, "result");
    }

    private PasswordDispatchResult dispatchNotClaimed(UUID operationId) {
        String state = state(operationId);
        if ("DISPATCHED".equals(state) || "UNCERTAIN".equals(state)
                || "REJECTED".equals(state) || "CONFIRMED".equals(state)
                || "COMPLETED".equals(state)) {
            return PasswordDispatchResult.ALREADY_CLAIMED;
        }
        return PasswordDispatchResult.NOT_CLAIMABLE;
    }

    private PasswordCredentialRecordResult recordedState(UUID operationId, String expected) {
        return expected.equals(state(operationId))
                ? PasswordCredentialRecordResult.ALREADY_RECORDED
                : PasswordCredentialRecordResult.NOT_RECORDABLE;
    }

    private String state(UUID operationId) {
        List<?> rows = entityManager.createNativeQuery(PasswordOperationSql.FIND_DISPATCH_STATE)
                .setParameter("operationId", operationId.toString())
                .getResultList();
        if (rows.size() > 1) {
            throw new UnexpectedPasswordOperationUpdateException();
        }
        return rows.isEmpty() ? null : (String) rows.getFirst();
    }

    private int update(String sql, UUID operationId) {
        int updated = entityManager.createNativeQuery(sql)
                .setParameter("operationId", operationId.toString())
                .executeUpdate();
        if (updated > 1) {
            throw new UnexpectedPasswordOperationUpdateException();
        }
        return updated;
    }

    private void insert(PasswordReservation reservation, UUID journeyId) {
        var operation = reservation.operation();
        var proofs = reservation.proofs();
        var fingerprints = reservation.fingerprints();
        String bindingId = operation.claimedBindingId() == null ? null
                : operation.claimedBindingId().toString();
        entityManager.createNativeQuery(PasswordOperationSql.INSERT_JOURNEY)
                .setParameter("journeyId", journeyId.toString())
                .setParameter("appId", operation.appId())
                .setParameter("installationHash", fingerprints.installation().bytes())
                .setParameter("requestJkt", proofs.requestKey().digest().bytes())
                .setParameter("requestPublicJwk", proofs.requestPublicJwk())
                .setParameter("bindingId", bindingId)
                .setParameter("responseJkt", proofs.responseKeyThumbprint().bytes())
                .setParameter("responsePublicJwk", proofs.responsePublicJwk())
                .setParameter("credentialDeadline", utc(reservation.credentialDeadline()))
                .setParameter("journeyDeadline", utc(reservation.journeyDeadline()))
                .setParameter("now", utc(reservation.now()))
                .executeUpdate();
        entityManager.createNativeQuery(PasswordOperationSql.INSERT_OPERATION)
                .setParameter("operationId", operation.operationId().toString())
                .setParameter("journeyId", journeyId.toString())
                .setParameter("appId", operation.appId())
                .setParameter("ownerScope", fingerprints.ownerScope().bytes())
                .setParameter("idempotency", fingerprints.idempotency().bytes())
                .setParameter("commandDigest", fingerprints.command().bytes())
                .setParameter("commandKeyId", fingerprints.commandKeyId())
                .setParameter("requestJkt", proofs.requestKey().digest().bytes())
                .setParameter("deadline", utc(reservation.credentialDeadline()))
                .setParameter("now", utc(reservation.now()))
                .executeUpdate();
    }

    private PasswordReservationResult findExisting(PasswordReservation reservation) {
        var fingerprints = reservation.fingerprints();
        List<?> rows = transactions.execute(status -> entityManager
                .createNativeQuery(PasswordOperationSql.FIND_BY_IDEMPOTENCY)
                .setParameter("ownerScope", fingerprints.ownerScope().bytes())
                .setParameter("idempotency", fingerprints.idempotency().bytes())
                .getResultList());
        if (rows == null || rows.isEmpty()) {
            return new PasswordReservationResult.Conflict();
        }
        if (rows.size() != 1) {
            throw new UnexpectedPasswordOperationUpdateException();
        }
        Object[] row = (Object[]) rows.getFirst();
        return new PasswordReservationResult.Existing(UUID.fromString((String) row[0]),
                UUID.fromString((String) row[1]), Digest32.fromBytes((byte[]) row[2]),
                (String) row[3]);
    }

    private Timestamp utc(java.time.Instant instant) {
        return Timestamp.from(instant);
    }
}
