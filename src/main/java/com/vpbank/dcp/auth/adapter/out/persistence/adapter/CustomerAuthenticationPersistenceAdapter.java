package com.vpbank.dcp.auth.adapter.out.persistence.adapter;

import com.vpbank.dcp.auth.adapter.out.persistence.entity.CustomerAuthenticationEntity;
import com.vpbank.dcp.auth.adapter.out.persistence.mapper.RegistrationPersistenceMapper;
import com.vpbank.dcp.auth.adapter.out.persistence.repository.CustomerAuthenticationJpaRepository;
import com.vpbank.dcp.auth.application.port.out.CustomerAuthentication;
import com.vpbank.dcp.auth.application.port.out.CustomerAuthenticationRepository;
import com.vpbank.dcp.auth.application.port.out.RepositoryUnavailableException;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.PasswordLockout;
import com.vpbank.dcp.auth.domain.model.UserName;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataAccessException;
import org.springframework.orm.ObjectOptimisticLockingFailureException;

import java.util.Optional;

/**
 * CUSTOMER_AUTHENTICATION for login: read by username (case-insensitive like the unique key),
 * lockout writes as compare-and-set on VERSION so two simultaneous failures count as two.
 */
@RequiredArgsConstructor
public class CustomerAuthenticationPersistenceAdapter implements CustomerAuthenticationRepository {
    @NonNull private final CustomerAuthenticationJpaRepository rows;

    @Override
    public Optional<CustomerAuthentication> findByUserName(UserName userName) {
        try {
            return rows.findByUserNameIgnoreCase(userName.value()).map(RegistrationPersistenceMapper::toIdentity);
        } catch (DataAccessException failure) {
            throw new RepositoryUnavailableException(failure);
        }
    }

    @Override
    public Optional<CustomerAuthentication> saveLockoutIfCurrent(CustomerAuthentication current, PasswordLockout changed) {
        try {
            Optional<CustomerAuthenticationEntity> row = rows.findById(current.customerId().value());
            if (row.isEmpty() || row.get().getVersion() != current.version()) {
                return Optional.empty();
            }
            RegistrationPersistenceMapper.applyLockout(row.get(), changed);
            // Detached row: @Version turns saveAndFlush into UPDATE … WHERE VERSION = ?.
            return Optional.of(RegistrationPersistenceMapper.toIdentity(rows.saveAndFlush(row.get())));
        } catch (ObjectOptimisticLockingFailureException stale) {
            return Optional.empty();
        } catch (DataAccessException failure) {
            throw new RepositoryUnavailableException(failure);
        }
    }

    @Override
    public boolean unlock(CustomerId customerId) {
        try {
            Optional<CustomerAuthenticationEntity> row = rows.findById(customerId.value());
            if (row.isEmpty()) {
                return false;
            }
            RegistrationPersistenceMapper.applyLockout(row.get(), PasswordLockout.none());
            rows.saveAndFlush(row.get());
            return true;
        } catch (DataAccessException failure) {
            throw new RepositoryUnavailableException(failure);
        }
    }
}
