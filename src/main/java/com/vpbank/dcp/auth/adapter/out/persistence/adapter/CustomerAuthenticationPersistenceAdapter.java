package com.vpbank.dcp.auth.adapter.out.persistence.adapter;

import com.vpbank.dcp.auth.adapter.out.persistence.mapper.RegistrationPersistenceMapper;
import com.vpbank.dcp.auth.adapter.out.persistence.repository.CustomerAuthenticationJpaRepository;
import com.vpbank.dcp.auth.application.port.out.CustomerAuthentication;
import com.vpbank.dcp.auth.application.port.out.CustomerAuthenticationRepository;
import com.vpbank.dcp.auth.application.port.out.RepositoryUnavailableException;
import com.vpbank.dcp.auth.domain.model.UserName;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataAccessException;

import java.util.Optional;

/** Read side of CUSTOMER_AUTHENTICATION for login: one row per username, case-insensitive like the unique key. */
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
}
