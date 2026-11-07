package com.vpbank.dcp.auth.application.port.out.model;

import com.vpbank.dcp.auth.domain.model.Email;
import com.vpbank.dcp.auth.domain.model.UserName;
import lombok.Builder;
import lombok.NonNull;

/** The user to create in the identity provider. {@code email} may be null. */
@Builder
public record NewIdentityUser(@NonNull UserName userName,
                              @NonNull String firstName,
                              @NonNull String lastName,
                              Email email,
                              boolean emailVerified) {
    @Override
    public String toString() {
        return "NewIdentityUser[userName=" + userName + ", redacted]";
    }
}
