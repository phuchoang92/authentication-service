package com.vpbank.dcp.infrastructure.persistence.repository;

import com.vpbank.dcp.core.domain.customer.VerifiedProviderIdentity;
import com.vpbank.dcp.core.port.out.password.PasswordOperationContext;
import com.vpbank.dcp.core.port.out.password.PasswordReservation;
import com.vpbank.dcp.core.port.out.password.PasswordReservationFingerprints;
import com.vpbank.dcp.core.port.out.password.VerifiedPasswordProofs;
import com.vpbank.dcp.infrastructure.persistence.projection.ConfirmedPasswordOwnerView;
import com.vpbank.dcp.infrastructure.persistence.projection.CustomerOwnerView;
import com.vpbank.dcp.infrastructure.persistence.projection.PasswordReservationView;
import com.vpbank.dcp.infrastructure.persistence.projection.VerifiedPasswordIdentityView;
import jakarta.persistence.EntityManager;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Repository;

/** Binds and maps password-operation SQL; never calls Keycloak or Redis. */
@Repository
public class PasswordOperationPersistenceRepository {

    private final EntityManager entityManager;

    public PasswordOperationPersistenceRepository(EntityManager entityManager) {
        this.entityManager = Objects.requireNonNull(entityManager, "entityManager");
    }

    public void insertJourney(PasswordReservation reservation, UUID journeyId) {
        PasswordOperationContext operation = reservation.operation();
        VerifiedPasswordProofs proofs = reservation.proofs();
        PasswordReservationFingerprints fingerprints = reservation.fingerprints();
        String bindingId = operation.claimedBindingId() == null ? null
                : operation.claimedBindingId().toString();
        exactlyOne(entityManager.createNativeQuery(PasswordOperationSql.INSERT_JOURNEY)
                .setParameter("journeyId", journeyId.toString())
                .setParameter("appId", operation.appId())
                .setParameter("installationHash", fingerprints.installation().bytes())
                .setParameter("requestJkt", proofs.requestKey().digest().bytes())
                .setParameter("requestPublicJwk", proofs.requestPublicJwk())
                .setParameter("bindingId", bindingId)
                .setParameter("deviceProofJkt", proofs.deviceKeyThumbprint() == null
                        ? null : proofs.deviceKeyThumbprint().bytes())
                .setParameter("responseJkt", proofs.responseKeyThumbprint().bytes())
                .setParameter("responsePublicJwk", proofs.responsePublicJwk())
                .setParameter("credentialDeadline", utc(reservation.credentialDeadline()))
                .setParameter("journeyDeadline", utc(reservation.journeyDeadline()))
                .setParameter("now", utc(reservation.now()))
                .executeUpdate());
    }

    public void insertOperation(PasswordReservation reservation, UUID journeyId) {
        PasswordOperationContext operation = reservation.operation();
        VerifiedPasswordProofs proofs = reservation.proofs();
        PasswordReservationFingerprints fingerprints = reservation.fingerprints();
        exactlyOne(entityManager.createNativeQuery(PasswordOperationSql.INSERT_OPERATION)
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
                .executeUpdate());
    }

    public Optional<PasswordReservationView> findExisting(PasswordReservation reservation) {
        PasswordReservationFingerprints fingerprints = reservation.fingerprints();
        List<?> rows = entityManager.createNativeQuery(PasswordOperationSql.FIND_BY_IDEMPOTENCY)
                .setParameter("ownerScope", fingerprints.ownerScope().bytes())
                .setParameter("idempotency", fingerprints.idempotency().bytes())
                .getResultList();
        if (rows.isEmpty()) {
            return Optional.empty();
        }
        if (rows.size() != 1) {
            throw new UnexpectedPasswordOperationUpdateException();
        }
        Object[] row = (Object[]) rows.getFirst();
        return Optional.of(new PasswordReservationView(UUID.fromString((String) row[0]),
                UUID.fromString((String) row[1]), (byte[]) row[2], (String) row[3]));
    }

    public UUID findJourneyId(UUID operationId) {
        List<?> rows = entityManager.createNativeQuery(PasswordOperationSql.FIND_JOURNEY_ID)
                .setParameter("operationId", operationId.toString()).getResultList();
        if (rows.size() > 1) {
            throw new UnexpectedPasswordOperationUpdateException();
        }
        return rows.isEmpty() ? null : UUID.fromString((String) rows.getFirst());
    }

    public void lockJourney(UUID journeyId) {
        List<?> rows = entityManager.createNativeQuery(PasswordOperationSql.LOCK_JOURNEY)
                .setParameter("journeyId", journeyId.toString()).getResultList();
        if (rows.size() != 1) {
            throw new UnexpectedPasswordOperationUpdateException();
        }
    }

    public int claimJourney(UUID journeyId) {
        return updateJourney(PasswordOperationSql.CLAIM_JOURNEY_FOR_DISPATCH, journeyId);
    }

    public int claimDispatch(UUID operationId) {
        return updateOperation(PasswordOperationSql.CLAIM_DISPATCH, operationId);
    }

    public int rejectJourney(UUID journeyId) {
        return updateJourney(PasswordOperationSql.REJECT_JOURNEY, journeyId);
    }

    public int rejectOperation(UUID operationId) {
        return updateOperation(PasswordOperationSql.REJECT_OPERATION, operationId);
    }

    public int recordUncertain(UUID operationId) {
        return updateOperation(PasswordOperationSql.RECORD_UNCERTAIN, operationId);
    }

    public int recordMfaUnavailableJourney(UUID journeyId, String route) {
        return exactlyZeroOrOne(entityManager.createNativeQuery(
                        PasswordOperationSql.RECORD_MFA_UNAVAILABLE_JOURNEY)
                .setParameter("journeyId", journeyId.toString())
                .setParameter("route", route)
                .executeUpdate());
    }

    public int recordMfaUnavailableOperation(UUID operationId) {
        return updateOperation(PasswordOperationSql.RECORD_MFA_UNAVAILABLE_OPERATION, operationId);
    }

    public int recordVerifiedIdentity(UUID operationId, VerifiedProviderIdentity identity) {
        int updated = entityManager.createNativeQuery(PasswordOperationSql.RECORD_VERIFIED_IDENTITY)
                .setParameter("operationId", operationId.toString())
                .setParameter("issuer", identity.issuer())
                .setParameter("subject", identity.subject())
                .executeUpdate();
        return exactlyZeroOrOne(updated);
    }

    public Optional<VerifiedPasswordIdentityView> verifiedIdentityForReconciliation(UUID operationId) {
        List<?> rows = entityManager.createNativeQuery(PasswordOperationSql.READ_VERIFIED_IDENTITY)
                .setParameter("operationId", operationId.toString()).getResultList();
        if (rows.isEmpty()) {
            return Optional.empty();
        }
        if (rows.size() != 1) {
            throw new UnexpectedPasswordOperationUpdateException();
        }
        Object[] row = (Object[]) rows.getFirst();
        return Optional.of(new VerifiedPasswordIdentityView((String) row[0], (String) row[1]));
    }

    public Optional<ConfirmedPasswordOwnerView> confirmedOwner(UUID operationId) {
        List<?> rows = entityManager.createNativeQuery(PasswordOperationSql.READ_CONFIRMED_OWNER)
                .setParameter("operationId", operationId.toString()).getResultList();
        if (rows.isEmpty()) {
            return Optional.empty();
        }
        if (rows.size() != 1) {
            throw new UnexpectedPasswordOperationUpdateException();
        }
        Object[] row = (Object[]) rows.getFirst();
        CustomerOwnerView customer = new CustomerOwnerView(UUID.fromString((String) row[2]),
                (String) row[3], (String) row[4], ((Number) row[5]).longValue(),
                ((Number) row[6]).longValue(), ((LocalDateTime) row[7]).toInstant(ZoneOffset.UTC));
        return Optional.of(new ConfirmedPasswordOwnerView((String) row[0], (String) row[1], customer));
    }

    public String operationState(UUID operationId) {
        List<?> rows = entityManager.createNativeQuery(PasswordOperationSql.LOCK_DISPATCH_STATE)
                .setParameter("operationId", operationId.toString()).getResultList();
        if (rows.size() > 1) {
            throw new UnexpectedPasswordOperationUpdateException();
        }
        return rows.isEmpty() ? null : (String) rows.getFirst();
    }

    private int updateJourney(String sql, UUID journeyId) {
        int updated = entityManager.createNativeQuery(sql)
                .setParameter("journeyId", journeyId.toString()).executeUpdate();
        return exactlyZeroOrOne(updated);
    }

    private int updateOperation(String sql, UUID operationId) {
        int updated = entityManager.createNativeQuery(sql)
                .setParameter("operationId", operationId.toString()).executeUpdate();
        return exactlyZeroOrOne(updated);
    }

    private void exactlyOne(int updated) {
        if (updated != 1) {
            throw new UnexpectedPasswordOperationUpdateException();
        }
    }

    private int exactlyZeroOrOne(int updated) {
        if (updated > 1) {
            throw new UnexpectedPasswordOperationUpdateException();
        }
        return updated;
    }

    private Timestamp utc(Instant instant) {
        return Timestamp.from(instant);
    }
}
