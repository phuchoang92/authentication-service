package com.vpbank.dcp.infrastructure.config;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.vpbank.dcp.core.password.PasswordVerifier;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.StrictJoseJson;
import com.vpbank.dcp.infrastructure.adapter.out.keycloak.KeycloakClientAuthentication;
import com.vpbank.dcp.infrastructure.adapter.out.keycloak.KeycloakClientSecretAuthentication;
import com.vpbank.dcp.infrastructure.adapter.out.keycloak.KeycloakPrivateKeyJwtAuthentication;
import com.vpbank.dcp.infrastructure.config.properties.KeycloakClientAuthenticationMethod;
import com.vpbank.dcp.infrastructure.config.properties.KeycloakPrivateClientProperties;
import java.net.http.HttpClient;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;

class KeycloakPrivateClientConfigurationTest {

    private static final String PREFIX = "auth.keycloak.private-client.";
    private final String privateJwk;
    private final WebApplicationContextRunner context;

    KeycloakPrivateClientConfigurationTest() throws Exception {
        var key = new ECKeyGenerator(Curve.P_256).keyID("test-key").generate();
        privateJwk = key.toJSONString();
        context = new WebApplicationContextRunner()
                .withUserConfiguration(KeycloakPrivateClientConfiguration.class)
                .withBean(HttpClient.class, HttpClient::newHttpClient)
                .withBean(StrictJoseJson.class, StrictJoseJson::new)
                .withPropertyValues(
                        PREFIX + "token-audience=https://kc.bank.test/realms/bank/protocol/openid-connect/token",
                        PREFIX + "request-timeout-ms=1000",
                        "auth.keycloak.id-token-trust.issuer=https://kc.bank.test/realms/bank",
                        "auth.keycloak.id-token-trust.key-id=test-key",
                        "auth.keycloak.id-token-trust.public-jwk=" + key.toPublicJWK().toJSONString());
    }

    @Test
    void secretModeStartsWithConfiguredClientIdAndWithoutPrivateKey() {
        context.withPropertyValues(PREFIX + "authentication-method=CLIENT_SECRET_POST",
                PREFIX + "client-id=bank-auth-secret", PREFIX + "client-secret=test-only-secret")
                .run(started -> {
                    assertThat(started).hasNotFailed().hasSingleBean(PasswordVerifier.class);
                    assertThat(started.getBean(KeycloakClientAuthentication.class))
                            .isInstanceOf(KeycloakClientSecretAuthentication.class);
                    var properties = started.getBean(KeycloakPrivateClientProperties.class);
                    assertThat(properties.clientId()).isEqualTo("bank-auth-secret");
                    assertThat(properties.toString()).isEqualTo("KeycloakPrivateClientProperties[redacted]");
                    assertThat(properties.privateJwk()).isNull();
                });
    }

    @Test
    void defaultsPreservePrivateKeyJwtAndExistingClientIdWithoutRequiringSecret() {
        context.withPropertyValues(PREFIX + "private-jwk=" + privateJwk).run(started -> {
            assertThat(started).hasNotFailed().hasSingleBean(PasswordVerifier.class);
            assertThat(started.getBean(KeycloakClientAuthentication.class))
                    .isInstanceOf(KeycloakPrivateKeyJwtAuthentication.class);
            var properties = started.getBean(KeycloakPrivateClientProperties.class);
            assertThat(properties.clientId()).isEqualTo("authentication-service");
            assertThat(properties.authenticationMethod()).isEqualTo(KeycloakClientAuthenticationMethod.PRIVATE_KEY_JWT);
            assertThat(properties.clientSecret()).isNull();
        });
    }

    @Test
    void onlyTheSelectedCredentialIsParsed() {
        context.withPropertyValues(PREFIX + "authentication-method=CLIENT_SECRET_POST",
                PREFIX + "client-secret=test-only-secret", PREFIX + "private-jwk=unused-invalid-key")
                .run(started -> assertThat(started).hasNotFailed());
    }

    @Test
    void missingOrBlankSelectedCredentialPreventsStartupEvenWhenOtherModeHasCredentials() {
        context.withPropertyValues(PREFIX + "authentication-method=CLIENT_SECRET_POST",
                PREFIX + "private-jwk=" + privateJwk).run(started -> assertThat(started).hasFailed());
        context.withPropertyValues(PREFIX + "authentication-method=CLIENT_SECRET_POST",
                PREFIX + "client-secret= ").run(started -> assertThat(started).hasFailed());
        context.withPropertyValues(PREFIX + "client-secret=test-only-secret")
                .run(started -> assertThat(started).hasFailed());
    }

    @Test
    void unknownModeBlankClientIdAndInvalidSelectedKeyPreventStartup() {
        context.withPropertyValues(PREFIX + "authentication-method=UNKNOWN",
                PREFIX + "private-jwk=" + privateJwk).run(started -> assertThat(started).hasFailed());
        context.withPropertyValues(PREFIX + "client-id= ", PREFIX + "private-jwk=" + privateJwk)
                .run(started -> assertThat(started).hasFailed());
        context.withPropertyValues(PREFIX + "private-jwk=invalid-test-key")
                .run(started -> assertThat(started).hasFailed());
    }
}
