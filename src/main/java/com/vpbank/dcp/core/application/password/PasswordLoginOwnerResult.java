package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.domain.customer.CustomerAuthenticationState;
import java.util.UUID;

/** Owner acceptance is internal; it does not authorize session activation. */
public sealed interface PasswordLoginOwnerResult {

    record Accepted(UUID subjectId, CustomerAuthenticationState customer)
            implements PasswordLoginOwnerResult { }

    record Rejected() implements PasswordLoginOwnerResult { }

    record Unavailable() implements PasswordLoginOwnerResult { }

    record NotClaimable() implements PasswordLoginOwnerResult { }
}
