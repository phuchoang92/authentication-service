package com.vpbank.dcp.infrastructure.adapter.out.persistence.password;

import com.vpbank.dcp.core.domain.customer.VerifiedProviderIdentity;
import com.vpbank.dcp.core.domain.device.TrustedDeviceRoute;
import com.vpbank.dcp.core.port.out.password.ConfirmedPasswordOwner;
import com.vpbank.dcp.core.port.out.password.PasswordCredentialRecordResult;
import com.vpbank.dcp.core.port.out.password.InvalidPasswordOperationException;
import com.vpbank.dcp.core.port.out.password.PasswordDispatchResult;
import com.vpbank.dcp.core.port.out.password.PasswordOperationStore;
import com.vpbank.dcp.core.port.out.password.PasswordOperationProgress;
import com.vpbank.dcp.core.port.out.password.PasswordReservation;
import com.vpbank.dcp.core.port.out.password.PasswordReservationResult;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import org.hibernate.exception.ConstraintViolationException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.support.TransactionTemplate;

/** Owns short SQL transaction boundaries; the repository owns statements and mapping. */
@Repository
public class JpaPasswordOperationStore implements PasswordOperationStore {

    private final PasswordOperationRepository repository;
    private final TransactionTemplate transactions;

    public JpaPasswordOperationStore(PasswordOperationRepository repository,
                                     TransactionTemplate transactions) {
        this.repository = Objects.requireNonNull(repository, "repository");
        this.transactions = Objects.requireNonNull(transactions, "transactions");
    }

    @Override
    public PasswordReservationResult reserve(PasswordReservation reservation) {
        Objects.requireNonNull(reservation, "reservation");
        UUID journeyId = UUID.randomUUID();
        try {
            transactions.executeWithoutResult(status -> repository.insert(reservation, journeyId));
            return new PasswordReservationResult.Created(journeyId);
        } catch (DataIntegrityViolationException duplicate) {
            if (!isOperationDuplicate(duplicate)) {
                throw duplicate;
            }
            return transactions.execute(status -> repository.findExisting(reservation));
        }
    }

    @Override
    public PasswordDispatchResult claimDispatch(UUID operationId) {
        Objects.requireNonNull(operationId, "operationId");
        PasswordDispatchResult result = transactions.execute(status -> {
            UUID journeyId = repository.findJourneyId(operationId);
            if (journeyId == null) {
                return PasswordDispatchResult.NOT_CLAIMABLE;
            }
            repository.lockJourney(journeyId);
            if (repository.claimJourney(journeyId) == 0) {
                return dispatchNotClaimed(operationId);
            }
            if (repository.claimDispatch(operationId) != 1) {
                status.setRollbackOnly();
                return PasswordDispatchResult.NOT_CLAIMABLE;
            }
            return PasswordDispatchResult.CLAIMED;
        });
        return Objects.requireNonNull(result, "result");
    }

    @Override
    public PasswordOperationProgress progress(UUID operationId) {
        Objects.requireNonNull(operationId, "operationId");
        return repository.progress(operationId);
    }

    @Override
    public PasswordCredentialRecordResult recordVerifiedIdentity(
            UUID operationId, VerifiedProviderIdentity identity) {
        Objects.requireNonNull(operationId, "operationId");
        Objects.requireNonNull(identity, "identity");
        PasswordCredentialRecordResult result = transactions.execute(status -> {
            if (repository.recordVerifiedIdentity(operationId, identity) == 1) {
                return PasswordCredentialRecordResult.RECORDED;
            }
            Optional<VerifiedProviderIdentity> recorded = repository.verifiedIdentity(operationId);
            return recorded.filter(identity::equals).isPresent()
                    ? PasswordCredentialRecordResult.ALREADY_RECORDED
                    : PasswordCredentialRecordResult.NOT_RECORDABLE;
        });
        return Objects.requireNonNull(result, "result");
    }

    @Override
    public Optional<VerifiedProviderIdentity> verifiedIdentity(UUID operationId) {
        Objects.requireNonNull(operationId, "operationId");
        return repository.verifiedIdentity(operationId);
    }

    @Override
    public Optional<ConfirmedPasswordOwner> confirmedOwner(UUID operationId) {
        Objects.requireNonNull(operationId, "operationId");
        return repository.confirmedOwner(operationId);
    }

    @Override
    public PasswordCredentialRecordResult recordMfaUnavailable(UUID operationId,
                                                               TrustedDeviceRoute route) {
        Objects.requireNonNull(operationId, "operationId");
        if (route != TrustedDeviceRoute.OTHER_TRUSTED
                && route != TrustedDeviceRoute.NEW_DEVICE) {
            throw new InvalidPasswordOperationException();
        }
        return Objects.requireNonNull(transactions.execute(status -> {
            UUID journeyId = repository.findJourneyId(operationId);
            if (journeyId == null) {
                return PasswordCredentialRecordResult.NOT_RECORDABLE;
            }
            repository.lockJourney(journeyId);
            if (repository.recordMfaUnavailableJourney(journeyId, route.name()) != 1) {
                return recordedState(operationId, "MFA_UNAVAILABLE");
            }
            if (repository.recordMfaUnavailableOperation(operationId) != 1) {
                status.setRollbackOnly();
                return PasswordCredentialRecordResult.NOT_RECORDABLE;
            }
            return PasswordCredentialRecordResult.RECORDED;
        }));
    }

    @Override
    public PasswordCredentialRecordResult recordRejection(UUID operationId) {
        Objects.requireNonNull(operationId, "operationId");
        PasswordCredentialRecordResult result = transactions.execute(status -> {
            UUID journeyId = repository.findJourneyId(operationId);
            if (journeyId == null) {
                return PasswordCredentialRecordResult.NOT_RECORDABLE;
            }
            repository.lockJourney(journeyId);
            String current = repository.operationState(operationId);
            if (!"DISPATCHED".equals(current) && !"VERIFIED".equals(current)) {
                return recordedState(operationId, "REJECTED");
            }
            if (repository.rejectJourney(journeyId) == 0) {
                return recordedState(operationId, "REJECTED");
            }
            if (repository.rejectOperation(operationId) != 1) {
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
        PasswordCredentialRecordResult result = transactions.execute(status ->
                repository.recordUncertain(operationId) == 1
                        ? PasswordCredentialRecordResult.RECORDED
                        : recordedState(operationId, "UNCERTAIN"));
        return Objects.requireNonNull(result, "result");
    }

    private PasswordDispatchResult dispatchNotClaimed(UUID operationId) {
        String state = repository.operationState(operationId);
        if ("DISPATCHED".equals(state) || "VERIFIED".equals(state)
                || "UNCERTAIN".equals(state)
                || "REJECTED".equals(state) || "CONFIRMED".equals(state)
                || "MFA_UNAVAILABLE".equals(state)
                || "COMPLETED".equals(state)) {
            return PasswordDispatchResult.ALREADY_CLAIMED;
        }
        return PasswordDispatchResult.NOT_CLAIMABLE;
    }

    private PasswordCredentialRecordResult recordedState(UUID operationId, String expected) {
        return expected.equals(repository.operationState(operationId))
                ? PasswordCredentialRecordResult.ALREADY_RECORDED
                : PasswordCredentialRecordResult.NOT_RECORDABLE;
    }

    private boolean isOperationDuplicate(DataIntegrityViolationException failure) {
        if (!(failure.getCause() instanceof ConstraintViolationException constraint)
                || constraint.getSQLException().getErrorCode() != 1062) {
            return false;
        }
        String name = constraint.getConstraintName();
        return "auth_operation.PRIMARY".equals(name)
                || "auth_operation.uq_operation_idempotency".equals(name);
    }
}
