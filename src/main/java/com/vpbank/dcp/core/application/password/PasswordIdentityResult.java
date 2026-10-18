package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.domain.customer.SubjectId;
import com.vpbank.dcp.core.domain.customer.CustomerAuthenticationState;

/** One password attempt plus Customer eligibility and immutable owner acceptance. */
public sealed interface PasswordIdentityResult {

    record Verified(SubjectId subject, CustomerAuthenticationState customer)
            implements PasswordIdentityResult { }

    record Denied(LoginDenial why) implements PasswordIdentityResult { }
}
