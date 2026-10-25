package com.vpbank.dcp.core.password;

import com.vpbank.dcp.core.customer.SubjectId;
import com.vpbank.dcp.core.customer.CustomerAuthenticationState;

/** One password attempt plus Customer eligibility and immutable owner acceptance. */
public sealed interface PasswordIdentityResult {

    record Verified(SubjectId subject, CustomerAuthenticationState customer)
            implements PasswordIdentityResult { }

    record Denied(LoginDenial why) implements PasswordIdentityResult { }
}
