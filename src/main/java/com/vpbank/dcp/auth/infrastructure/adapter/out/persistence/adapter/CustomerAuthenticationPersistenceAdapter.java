package com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.adapter;

import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.port.out.model.CustomerAuthentication;
import com.vpbank.dcp.auth.application.port.out.repository.CustomerAuthenticationRepository;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.PasswordLockout;
import com.vpbank.dcp.auth.domain.model.UserName;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.entity.CustomerAuthenticationEntity;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.mapper.RegistrationPersistenceMapper;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.CustomerAuthenticationJpaRepository;
import java.util.Optional;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataAccessException;
import org.springframework.orm.ObjectOptimisticLockingFailureException;

/**
 * CUSTOMER_AUTHENTICATION for login: read by username (case-insensitive like the unique key),
 * lockout writes as compare-and-set on VERSION so two simultaneous failures count as two.
 */
@RequiredArgsConstructor
public class CustomerAuthenticationPersistenceAdapter implements CustomerAuthenticationRepository {
    @NonNull private final CustomerAuthenticationJpaRepository customerAuthenticationJpaRepository;

    @Override
    public Optional<CustomerAuthentication> findByUserName(UserName userName) {
        try {
            return customerAuthenticationJpaRepository.findByUserNameIgnoreCase(userName.value())
                    .map(RegistrationPersistenceMapper::toIdentity);
        } catch (DataAccessException failure) {
            throw new RepositoryUnavailableException(failure);
        }
    }

    @Override
    public Optional<CustomerAuthentication> saveLockoutIfCurrent(CustomerAuthentication currentIdentity,
                                                                 PasswordLockout changedLockout) {
        try {
            Optional<CustomerAuthenticationEntity> currentIdentityEntity =
                    customerAuthenticationJpaRepository.findById(currentIdentity.customerId().value());
            if (currentIdentityEntity.isEmpty()) {
                return Optional.empty();
            }
            CustomerAuthenticationEntity identityEntity = currentIdentityEntity.get();

            boolean isCurrentVersion = identityEntity.getVersion() == currentIdentity.version();
            if (!isCurrentVersion) {
                return Optional.empty();
            }

            RegistrationPersistenceMapper.applyLockout(identityEntity, changedLockout);

            // Detached row: @Version turns saveAndFlush into UPDATE … WHERE VERSION = ?.
            CustomerAuthenticationEntity savedIdentityEntity =
                    customerAuthenticationJpaRepository.saveAndFlush(identityEntity);
            CustomerAuthentication savedIdentity = RegistrationPersistenceMapper.toIdentity(savedIdentityEntity);
            return Optional.of(savedIdentity);
        } catch (ObjectOptimisticLockingFailureException stale) {
            return Optional.empty();
        } catch (DataAccessException failure) {
            throw new RepositoryUnavailableException(failure);
        }
    }

    @Override
    public boolean unlock(CustomerId customerId) {
        try {
            Optional<CustomerAuthenticationEntity> currentIdentityEntity =
                    customerAuthenticationJpaRepository.findById(customerId.value());
            if (currentIdentityEntity.isEmpty()) {
                return false;
            }
            CustomerAuthenticationEntity identityEntity = currentIdentityEntity.get();

            RegistrationPersistenceMapper.applyLockout(identityEntity, PasswordLockout.none());
            customerAuthenticationJpaRepository.saveAndFlush(identityEntity);

            return true;
        } catch (DataAccessException failure) {
            throw new RepositoryUnavailableException(failure);
        }
    }
}
