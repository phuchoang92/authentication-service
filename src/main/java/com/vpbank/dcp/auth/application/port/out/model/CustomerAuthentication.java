package com.vpbank.dcp.auth.application.port.out.model;

import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.PasswordLockout;
import com.vpbank.dcp.auth.domain.model.UserName;
import lombok.Builder;
import lombok.NonNull;

/**
 * A customer's login identity as stored: which Keycloak user it is, whether it may log in, and
 * its password lockout state. {@code version} is the row version the repository must still see
 * when it saves a lockout change.
 */
@Builder(toBuilder = true)
public record CustomerAuthentication(@NonNull CustomerId customerId,
                                     @NonNull UserName userName,
                                     @NonNull String identityIssuer,
                                     @NonNull String identitySubject,
                                     @NonNull String status,
                                     @NonNull PasswordLockout lockout,
                                     long version) {
    public static final String ACTIVE = "ACTIVE";


    public boolean isActive() {
        return ACTIVE.equals(status);
    }

    public boolean isSameIdentity(String issuer, String subject) {
        return identityIssuer.equals(issuer) && identitySubject.equals(subject);
    }
}
