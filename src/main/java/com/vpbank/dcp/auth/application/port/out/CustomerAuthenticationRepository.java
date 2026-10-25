package com.vpbank.dcp.auth.application.port.out;

import com.vpbank.dcp.auth.domain.model.UserName;

import java.util.Optional;

/** The identity rows registration wrote (CUSTOMER_AUTHENTICATION). Throws {@link RepositoryUnavailableException}. */
public interface CustomerAuthenticationRepository {
    Optional<CustomerAuthentication> findByUserName(UserName userName);
}
