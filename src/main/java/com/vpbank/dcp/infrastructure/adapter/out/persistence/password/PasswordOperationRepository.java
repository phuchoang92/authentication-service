package com.vpbank.dcp.infrastructure.adapter.out.persistence.password;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.customer.VerifiedProviderIdentity;
import com.vpbank.dcp.core.domain.customer.CustomerAuthenticationState;
import com.vpbank.dcp.core.domain.customer.CustomerStatus;
import com.vpbank.dcp.core.port.out.password.ConfirmedPasswordOwner;
import com.vpbank.dcp.core.port.out.password.PasswordReservation;
import com.vpbank.dcp.core.port.out.password.PasswordOperationContext;
import com.vpbank.dcp.core.port.out.password.PasswordOperationProgress;
import com.vpbank.dcp.core.port.out.password.PasswordReservationFingerprints;
import com.vpbank.dcp.core.port.out.password.PasswordReservationResult;
import com.vpbank.dcp.core.port.out.password.VerifiedPasswordProofs;
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
class PasswordOperationRepository {

    private final EntityManager entityManager;

    PasswordOperationRepository(EntityManager entityManager) {
        this.entityManager = Objects.requireNonNull(entityManager, "entityManager");
    }

    void insert(PasswordReservation reservation, UUID journeyId) {
        PasswordOperationContext operation = reservation.operation();
        VerifiedPasswordProofs proofs = reservation.proofs();
        PasswordReservationFingerprints fingerprints = reservation.fingerprints();
        String bindingId = operation.claimedBindingId() == null ? null
                : operation.claimedBindingId().toString();
        entityManager.createNativeQuery(PasswordOperationSql.INSERT_JOURNEY)
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

    PasswordReservationResult findExisting(PasswordReservation reservation) {
        PasswordReservationFingerprints fingerprints = reservation.fingerprints();
        List<?> rows = entityManager.createNativeQuery(PasswordOperationSql.FIND_BY_IDEMPOTENCY)
                .setParameter("ownerScope", fingerprints.ownerScope().bytes())
                .setParameter("idempotency", fingerprints.idempotency().bytes())
                .getResultList();
        if (rows.isEmpty()) {
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

    UUID findJourneyId(UUID operationId) {
        List<?> rows = entityManager.createNativeQuery(PasswordOperationSql.FIND_JOURNEY_ID)
                .setParameter("operationId", operationId.toString()).getResultList();
        if (rows.size() > 1) {
            throw new UnexpectedPasswordOperationUpdateException();
        }
        return rows.isEmpty() ? null : UUID.fromString((String) rows.getFirst());
    }

    void lockJourney(UUID journeyId) {
        List<?> rows = entityManager.createNativeQuery(PasswordOperationSql.LOCK_JOURNEY)
                .setParameter("journeyId", journeyId.toString()).getResultList();
        if (rows.size() != 1) {
            throw new UnexpectedPasswordOperationUpdateException();
        }
    }

    int claimJourney(UUID journeyId) {
        return updateJourney(PasswordOperationSql.CLAIM_JOURNEY_FOR_DISPATCH, journeyId);
    }

    int claimDispatch(UUID operationId) {
        return updateOperation(PasswordOperationSql.CLAIM_DISPATCH, operationId);
    }

    int rejectJourney(UUID journeyId) {
        return updateJourney(PasswordOperationSql.REJECT_JOURNEY, journeyId);
    }

    int rejectOperation(UUID operationId) {
        return updateOperation(PasswordOperationSql.REJECT_OPERATION, operationId);
    }

    int recordUncertain(UUID operationId) {
        return updateOperation(PasswordOperationSql.RECORD_UNCERTAIN, operationId);
    }

    int recordMfaUnavailableJourney(UUID journeyId, String route) {
        return exactlyZeroOrOne(entityManager.createNativeQuery(
                        PasswordOperationSql.RECORD_MFA_UNAVAILABLE_JOURNEY)
                .setParameter("journeyId", journeyId.toString())
                .setParameter("route", route)
                .executeUpdate());
    }

    int recordMfaUnavailableOperation(UUID operationId) {
        return updateOperation(PasswordOperationSql.RECORD_MFA_UNAVAILABLE_OPERATION, operationId);
    }

    int recordVerifiedIdentity(UUID operationId, VerifiedProviderIdentity identity) {
        int updated = entityManager.createNativeQuery(PasswordOperationSql.RECORD_VERIFIED_IDENTITY)
                .setParameter("operationId", operationId.toString())
                .setParameter("issuer", identity.issuer())
                .setParameter("subject", identity.subject())
                .executeUpdate();
        return exactlyZeroOrOne(updated);
    }

    Optional<VerifiedProviderIdentity> verifiedIdentity(UUID operationId) {
        List<?> rows = entityManager.createNativeQuery(PasswordOperationSql.READ_VERIFIED_IDENTITY)
                .setParameter("operationId", operationId.toString()).getResultList();
        if (rows.isEmpty()) {
            return Optional.empty();
        }
        if (rows.size() != 1) {
            throw new UnexpectedPasswordOperationUpdateException();
        }
        Object[] row = (Object[]) rows.getFirst();
        return Optional.of(new VerifiedProviderIdentity((String) row[0], (String) row[1]));
    }

    Optional<ConfirmedPasswordOwner> confirmedOwner(UUID operationId) {
        List<?> rows = entityManager.createNativeQuery(PasswordOperationSql.READ_CONFIRMED_OWNER)
                .setParameter("operationId", operationId.toString()).getResultList();
        if (rows.isEmpty()) {
            return Optional.empty();
        }
        if (rows.size() != 1) {
            throw new UnexpectedPasswordOperationUpdateException();
        }
        Object[] row = (Object[]) rows.getFirst();
        CustomerAuthenticationState customer = new CustomerAuthenticationState(
                (String) row[3], CustomerStatus.valueOf((String) row[4]),
                ((Number) row[5]).longValue(), ((Number) row[6]).longValue(),
                ((LocalDateTime) row[7]).toInstant(ZoneOffset.UTC));
        return Optional.of(new ConfirmedPasswordOwner(
                new VerifiedProviderIdentity((String) row[0], (String) row[1]),
                customer, UUID.fromString((String) row[2])));
    }

    String operationState(UUID operationId) {
        List<?> rows = entityManager.createNativeQuery(PasswordOperationSql.LOCK_DISPATCH_STATE)
                .setParameter("operationId", operationId.toString()).getResultList();
        if (rows.size() > 1) {
            throw new UnexpectedPasswordOperationUpdateException();
        }
        return rows.isEmpty() ? null : (String) rows.getFirst();
    }

    PasswordOperationProgress progress(UUID operationId) {
        List<?> rows = entityManager.createNativeQuery(PasswordOperationSql.READ_PROGRESS)
                .setParameter("operationId", operationId.toString()).getResultList();
        if (rows.size() > 1) {
            throw new UnexpectedPasswordOperationUpdateException();
        }
        return rows.isEmpty() ? PasswordOperationProgress.MISSING
                : PasswordOperationProgress.valueOf((String) rows.getFirst());
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
