package com.vpbank.dcp.auth.adapter.out.persistence.adapter;

import com.vpbank.dcp.auth.adapter.out.persistence.entity.RegistrationEntity;
import com.vpbank.dcp.auth.adapter.out.persistence.mapper.RegistrationPersistenceMapper;
import com.vpbank.dcp.auth.adapter.out.persistence.repository.CustomerAuthenticationJpaRepository;
import com.vpbank.dcp.auth.adapter.out.persistence.repository.RegistrationJpaRepository;
import com.vpbank.dcp.auth.application.port.out.RegistrationRepository;
import com.vpbank.dcp.auth.application.port.out.RepositoryUnavailableException;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.Registration;
import com.vpbank.dcp.auth.domain.model.RegistrationState;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.orm.ObjectOptimisticLockingFailureException;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.function.Supplier;

/**
 * {@link RegistrationRepository} over Spring Data JPA. The database only stops races (the
 * unique keys of phase 1); every step rule was decided by the aggregate before it gets here.
 * Single-row steps run as the repository's own short transactions; {@link #complete} is the one
 * method that writes two tables and therefore owns a transaction. Spring exceptions never leave
 * this class: they become a port result or {@link RepositoryUnavailableException}.
 */
@RequiredArgsConstructor
public class RegistrationPersistenceAdapter implements RegistrationRepository {
    private static final Byte OPEN = 1;

    @NonNull private final RegistrationJpaRepository registrations;
    @NonNull private final CustomerAuthenticationJpaRepository identities;

    @Override
    public ReserveResult reserve(Registration reserved) {
        try {
            RegistrationEntity saved = registrations.saveAndFlush(RegistrationPersistenceMapper.toEntity(reserved));
            return new ReserveResult.Reserved(RegistrationPersistenceMapper.toDomain(saved));
        } catch (DataIntegrityViolationException taken) {
            // UQ_CAR_OPEN_CUSTOMER or UQ_CAR_OPEN_USERNAME: someone already has an open request.
            return translate(() -> registrations
                    .findByCustomerIdAndOpenSlot(reserved.customerId().value(), OPEN)
                    .<ReserveResult>map(open -> new ReserveResult.CustomerHasOpen(
                            RegistrationPersistenceMapper.toDomain(open)))
                    .orElseGet(ReserveResult.UserNameTaken::new));
        } catch (DataAccessException failure) {
            throw new RepositoryUnavailableException(failure);
        }
    }

    @Override
    public Optional<Registration> findLatest(CustomerId customerId) {
        return translate(() -> registrations
                .findFirstByCustomerIdOrderByCreatedAtDescRequestIdDesc(customerId.value())
                .map(RegistrationPersistenceMapper::toDomain));
    }

    @Override
    public Optional<Registration> save(Registration changed) {
        try {
            Optional<RegistrationEntity> current = registrations.findById(changed.id().value());
            if (current.isEmpty() || current.get().getVersion() != changed.version()) {
                return Optional.empty();
            }
            RegistrationPersistenceMapper.apply(current.get(), changed);
            // The row is detached here; @Version makes saveAndFlush a compare-and-set on VERSION.
            return Optional.of(RegistrationPersistenceMapper.toDomain(registrations.saveAndFlush(current.get())));
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
    public CompleteResult complete(Registration completed) {
        try {
            Optional<RegistrationEntity> locked = registrations.lockByRequestId(completed.id().value());
            if (locked.isEmpty() || locked.get().getVersion() != completed.version()
                    || locked.get().getState() != RegistrationState.SMS_ACCEPTED) {
                return CompleteResult.STALE;
            }
            if (identities.existsByUserNameIgnoreCase(completed.userName().value())) {
                return CompleteResult.IDENTITY_TAKEN;
            }
            identities.save(RegistrationPersistenceMapper.toIdentity(completed));
            RegistrationPersistenceMapper.apply(locked.get(), completed);
            registrations.flush();
            return CompleteResult.COMPLETED;
        } catch (DataAccessException failure) {
            throw new RepositoryUnavailableException(failure);
        }
    }

    private static <T> T translate(Supplier<T> call) {
        try {
            return call.get();
        } catch (DataAccessException failure) {
            throw new RepositoryUnavailableException(failure);
        }
    }
}
