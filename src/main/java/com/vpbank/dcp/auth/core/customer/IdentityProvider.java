package com.vpbank.dcp.auth.core.customer;

/**
 * Keycloak Admin. Throws {@link PartnerUnavailableException} when it cannot answer or the outcome
 * of a call is unknown.
 */
public interface IdentityProvider {

    /** Creates the user disabled, so nobody can log in before the SMS is accepted. */
    CreateUserResult createDisabledUser(String userName, String firstName, String lastName,
                                        String email, boolean emailVerified);

    /** Sets a permanent (not temporary) password. */
    void setPassword(String identitySubject, String password);

    void enable(String identitySubject);

    sealed interface CreateUserResult {
        record Created(String identityIssuer, String identitySubject) implements CreateUserResult { }

        record UserNameTaken() implements CreateUserResult { }
    }
}
