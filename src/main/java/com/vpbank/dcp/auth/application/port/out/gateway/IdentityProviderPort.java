package com.vpbank.dcp.auth.application.port.out.gateway;

import com.vpbank.dcp.auth.application.port.out.model.NewIdentityUser;

/**
 * Keycloak Admin. Throws {@link PartnerUnavailableException} when it cannot answer or the outcome
 * of a call is unknown.
 */
public interface IdentityProviderPort {

    /** Creates the user disabled, so nobody can log in before the SMS is accepted. */
    CreateUserResult createDisabledUser(NewIdentityUser user);

    /** Sets a permanent (not temporary) password. */
    void setPassword(String identitySubject, String password);

    void enable(String identitySubject);

    sealed interface CreateUserResult {
        record Created(String identityIssuer, String identitySubject) implements CreateUserResult { }

        record UserNameTaken() implements CreateUserResult { }
    }
}
