package com.vpbank.dcp.auth.application.port.out.model;

import com.vpbank.dcp.auth.domain.model.Email;
import com.vpbank.dcp.auth.domain.model.UserName;
import java.util.Objects;
import lombok.Builder;

/** The user to create in the identity provider. {@code email} may be null. */
@Builder
public record NewIdentityUser(UserName userName, String firstName, String lastName, Email email,
                              boolean emailVerified) {
    public NewIdentityUser {
        Objects.requireNonNull(userName, "userName");
        Objects.requireNonNull(firstName, "firstName");
        Objects.requireNonNull(lastName, "lastName");
    }

    @Override
    public String toString() {
        return "NewIdentityUser[userName=" + userName + ", redacted]";
    }
}
