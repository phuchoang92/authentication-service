package com.vpbank.dcp.auth.application.port.out.repository;

import com.vpbank.dcp.auth.application.port.out.model.CustomerAuthentication;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.PasswordLockout;
import com.vpbank.dcp.auth.domain.model.UserName;
import java.util.Optional;

/** The identity rows registration wrote (CUSTOMER_AUTHENTICATION). Throws {@link RepositoryUnavailableException}. */
public interface CustomerAuthenticationRepository {
    Optional<CustomerAuthentication> findByUserName(UserName userName);

    /**
     * Saves a lockout change only if the row still has {@code current.version()} (two failures
     * can arrive at the same moment); returns the stored row. Empty = stale.
     */
    Optional<CustomerAuthentication> saveLockoutIfCurrent(CustomerAuthentication current, PasswordLockout changed);

    /** The bank's unlock: status ACTIVE, count 0, no lockout time. False when the customer is unknown. */
    boolean unlock(CustomerId customerId);
}
