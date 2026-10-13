package com.vpbank.dcp.infrastructure.adapter.out.keycloak;

import com.vpbank.dcp.infrastructure.adapter.out.http.ExternalForm;
import java.time.Clock;
import java.util.Objects;

/** Creates a fresh signed assertion for each exchange, without a shared client secret. */
public final class KeycloakPrivateKeyJwtAuthentication implements KeycloakClientAuthentication {

    private static final String ASSERTION_TYPE =
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    private final PrivateKeyJwtFactory assertions;
    private final Clock clock;

    public KeycloakPrivateKeyJwtAuthentication(PrivateKeyJwtFactory assertions, Clock clock) {
        this.assertions = Objects.requireNonNull(assertions, "assertions");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public void addCredentials(ExternalForm form) {
        form.add("client_id", assertions.clientId())
                .add("client_assertion_type", ASSERTION_TYPE)
                .add("client_assertion", assertions.issue(clock.instant()));
    }
}
