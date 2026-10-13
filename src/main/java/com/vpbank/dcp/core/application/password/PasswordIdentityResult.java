package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.domain.customer.CustomerAuthenticationState;
import java.util.UUID;

/** Password and Customer outcome; it does not authorize a banking session. */
public sealed interface PasswordIdentityResult {
    record Verified(UUID customerId, CustomerAuthenticationState customer)
            implements PasswordIdentityResult { }

    record Rejected() implements PasswordIdentityResult { }

    record Unavailable() implements PasswordIdentityResult { }
}
