package com.vpbank.dcp.auth.application.port.out;

import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.UserName;
import lombok.Builder;

import java.util.Objects;

/** A customer's login identity as stored: which Keycloak user it is and whether it may log in. */
@Builder
public record CustomerAuthentication(CustomerId customerId, UserName userName, String identityIssuer,
                                     String identitySubject, String status) {
    public static final String ACTIVE = "ACTIVE";

    public CustomerAuthentication {
        Objects.requireNonNull(customerId, "customerId");
        Objects.requireNonNull(userName, "userName");
        Objects.requireNonNull(identityIssuer, "identityIssuer");
        Objects.requireNonNull(identitySubject, "identitySubject");
        Objects.requireNonNull(status, "status");
    }

    public boolean isActive() {
        return ACTIVE.equals(status);
    }

    public boolean isSameIdentity(String issuer, String subject) {
        return identityIssuer.equals(issuer) && identitySubject.equals(subject);
    }
}
