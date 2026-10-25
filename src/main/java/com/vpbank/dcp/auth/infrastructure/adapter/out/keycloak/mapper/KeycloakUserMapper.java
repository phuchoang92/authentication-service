package com.vpbank.dcp.auth.infrastructure.adapter.out.keycloak.mapper;

import com.vpbank.dcp.auth.application.port.out.model.NewIdentityUser;
import com.vpbank.dcp.auth.infrastructure.adapter.out.keycloak.dto.CreateUserRequest;
import com.vpbank.dcp.auth.infrastructure.adapter.out.keycloak.dto.CredentialRequest;
import com.vpbank.dcp.auth.infrastructure.adapter.out.keycloak.dto.EnableUserRequest;
import java.net.URI;
import java.util.List;
import java.util.Optional;

/** Port value types ↔ Keycloak Admin payloads. */
public final class KeycloakUserMapper {
    private KeycloakUserMapper() {
    }

    /** Disabled, no required actions: nobody can log in before the SMS is accepted. */
    public static CreateUserRequest toCreateUserRequest(NewIdentityUser user) {
        return CreateUserRequest.builder()
                .username(user.userName().value())
                .firstName(user.firstName())
                .lastName(user.lastName())
                .email(user.email() == null ? null : user.email().value())
                .emailVerified(user.email() == null ? null : user.emailVerified())
                .enabled(false)
                .requiredActions(List.of())
                .build();
    }

    public static CredentialRequest permanentPassword(String password) {
        return new CredentialRequest("password", password, false);
    }

    public static EnableUserRequest enabled() {
        return new EnableUserRequest(true);
    }

    /** The new user's ID is the last segment of the {@code Location} header. */
    public static Optional<String> subjectFrom(URI location) {
        if (location == null) {
            return Optional.empty();
        }
        String path = location.getPath();
        String subject = path.substring(path.lastIndexOf('/') + 1);
        return subject.isBlank() ? Optional.empty() : Optional.of(subject);
    }
}
