package com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.adapter;

import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.port.out.repository.RegistrationRepository;
import com.vpbank.dcp.auth.domain.enums.RegistrationState;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.Registration;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.entity.CustomerAuthenticationEntity;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.entity.RegistrationEntity;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.mapper.RegistrationPersistenceMapper;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.CustomerAuthenticationJpaRepository;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.RegistrationJpaRepository;
import java.util.Optional;
import java.util.function.Supplier;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.orm.ObjectOptimisticLockingFailureException;
import org.springframework.transaction.annotation.Transactional;

/**
 * {@link RegistrationRepository} over Spring Data JPA. The database only stops races (the
 * unique keys of phase 1); every step rule was decided by the aggregate before it gets here.
 * Single-row steps run as the repository's own short transactions; {@link #complete} is the one
 * method that writes two tables and therefore owns a transaction. Spring exceptions never leave
 * this class: they become a port result or {@link RepositoryUnavailableException}.
 */
@RequiredArgsConstructor
public class RegistrationPersistenceAdapter implements RegistrationRepository {
    /** The OPEN_SLOT marker of a request that is still in progress (NULL once finished). */
    private static final Byte OPEN = 1;

    @NonNull private final RegistrationJpaRepository registrationJpaRepository;
    @NonNull private final CustomerAuthenticationJpaRepository customerAuthenticationJpaRepository;

    @Override
    public ReserveResult reserve(Registration reservedRegistration) {
        RegistrationEntity newRegistrationEntity = RegistrationPersistenceMapper.toEntity(reservedRegistration);
        try {
            RegistrationEntity savedRegistrationEntity = registrationJpaRepository.saveAndFlush(newRegistrationEntity);
            Registration savedRegistration = RegistrationPersistenceMapper.toDomain(savedRegistrationEntity);
            return new ReserveResult.Reserved(savedRegistration);
        } catch (DataIntegrityViolationException taken) {
            // UQ_CAR_OPEN_CUSTOMER or UQ_CAR_OPEN_USERNAME: someone already has an open request.
            return translate(() -> answerForTakenSlot(reservedRegistration));
        } catch (DataAccessException failure) {
            throw new RepositoryUnavailableException(failure);
        }
    }

    /** This customer's own open request wins over a username taken by somebody else. */
    private ReserveResult answerForTakenSlot(Registration reservedRegistration) {
        Optional<RegistrationEntity> openRegistrationEntity = registrationJpaRepository
                .findByCustomerIdAndOpenSlot(reservedRegistration.customerId().value(), OPEN);
        if (openRegistrationEntity.isEmpty()) {
            return new ReserveResult.UserNameTaken();
        }
        Registration openRegistration = RegistrationPersistenceMapper.toDomain(openRegistrationEntity.get());
        return new ReserveResult.CustomerHasOpen(openRegistration);
    }

    @Override
    public Optional<Registration> findLatest(CustomerId customerId) {
        return translate(() -> registrationJpaRepository
                .findFirstByCustomerIdOrderByCreatedAtDescRequestIdDesc(customerId.value())
                .map(RegistrationPersistenceMapper::toDomain));
    }

    @Override
    public Optional<Registration> save(Registration changedRegistration) {
        try {
            Optional<RegistrationEntity> currentRegistrationEntity =
                    registrationJpaRepository.findById(changedRegistration.id().value());
            if (currentRegistrationEntity.isEmpty()) {
                return Optional.empty();
            }
            RegistrationEntity registrationEntity = currentRegistrationEntity.get();

            boolean isCurrentVersion = registrationEntity.getVersion() == changedRegistration.version();
            if (!isCurrentVersion) {
                return Optional.empty();
            }

            RegistrationPersistenceMapper.apply(registrationEntity, changedRegistration);

            // The row is detached here; @Version makes saveAndFlush a compare-and-set on VERSION.
            RegistrationEntity savedRegistrationEntity = registrationJpaRepository.saveAndFlush(registrationEntity);
            Registration savedRegistration = RegistrationPersistenceMapper.toDomain(savedRegistrationEntity);
            return Optional.of(savedRegistration);
        } catch (ObjectOptimisticLockingFailureException stale) {
            return Optional.empty();
        } catch (DataAccessException failure) {
            throw new RepositoryUnavailableException(failure);
        }
    }

    /**
     * Identity row + READY in one transaction, from a locked SMS_ACCEPTED row at the expected
     * version. The username conflict is pre-checked by query so it is a result, not a rollback;
     * a lost race on UQ_CA_USER_NAME is thrown, which rolls the transaction back.
     */
    @Override
    @Transactional
    public CompleteResult complete(Registration completedRegistration) {
        try {
            Optional<RegistrationEntity> lockedRegistrationEntity =
                    registrationJpaRepository.lockByRequestId(completedRegistration.id().value());
            if (lockedRegistrationEntity.isEmpty()) {
                return CompleteResult.STALE;
            }
            RegistrationEntity registrationEntity = lockedRegistrationEntity.get();

            boolean isCurrentVersion = registrationEntity.getVersion() == completedRegistration.version();
            boolean isSmsAccepted = registrationEntity.getState() == RegistrationState.SMS_ACCEPTED;
            if (!isCurrentVersion || !isSmsAccepted) {
                return CompleteResult.STALE;
            }

            boolean userNameTaken = customerAuthenticationJpaRepository
                    .existsByUserNameIgnoreCase(completedRegistration.userName().value());
            if (userNameTaken) {
                return CompleteResult.IDENTITY_TAKEN;
            }

            CustomerAuthenticationEntity identityEntity = RegistrationPersistenceMapper.toIdentity(completedRegistration);
            customerAuthenticationJpaRepository.save(identityEntity);

            RegistrationPersistenceMapper.apply(registrationEntity, completedRegistration);
            registrationJpaRepository.flush();

            return CompleteResult.COMPLETED;
        } catch (DataAccessException failure) {
            throw new RepositoryUnavailableException(failure);
        }
    }

    private static <T> T translate(Supplier<T> repositoryCall) {
        try {
            return repositoryCall.get();
        } catch (DataAccessException failure) {
            throw new RepositoryUnavailableException(failure);
        }
    }
}
