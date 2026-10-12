package com.vpbank.dcp.infrastructure.config;

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.vpbank.dcp.core.port.out.keycloak.DirectGrantPasswordVerifier;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.StrictJoseJson;
import com.vpbank.dcp.infrastructure.adapter.out.keycloak.DirectGrantTokenClient;
import com.vpbank.dcp.infrastructure.adapter.out.keycloak.InvalidKeycloakClientConfigurationException;
import com.vpbank.dcp.infrastructure.adapter.out.keycloak.KeycloakIdTokenVerifier;
import com.vpbank.dcp.infrastructure.adapter.out.keycloak.KeycloakDirectGrantPasswordVerifier;
import com.vpbank.dcp.infrastructure.adapter.out.keycloak.KeycloakTokenEndpoints;
import com.vpbank.dcp.infrastructure.adapter.out.keycloak.PrivateKeyJwtFactory;
import com.vpbank.dcp.infrastructure.adapter.out.http.ExternalEndpoint;
import com.vpbank.dcp.infrastructure.adapter.out.http.ExternalHttpClient;
import com.vpbank.dcp.infrastructure.adapter.out.http.ExternalHttpSettings;
import com.vpbank.dcp.infrastructure.config.properties.KeycloakIdTokenTrustProperties;
import com.vpbank.dcp.infrastructure.config.properties.KeycloakPrivateClientProperties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.net.URI;
import java.net.http.HttpClient;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.util.Set;
import tools.jackson.databind.JsonNode;

@Configuration(proxyBeanMethods = false)
@ConditionalOnWebApplication
@EnableConfigurationProperties({KeycloakPrivateClientProperties.class, KeycloakIdTokenTrustProperties.class})
public class KeycloakPrivateClientConfiguration {

    private static final int MAX_TOKEN_RESPONSE_BYTES = 65_536;

    @Bean
    PrivateKeyJwtFactory privateKeyJwtFactory(KeycloakPrivateClientProperties properties) {
        try {
            return new PrivateKeyJwtFactory(URI.create(properties.tokenAudience()),
                    ECKey.parse(properties.privateJwk()));
        } catch (IllegalArgumentException | ParseException failure) {
            throw new InvalidKeycloakClientConfigurationException(failure);
        }
    }

    @Bean
    DirectGrantPasswordVerifier directGrantPasswordVerifier(HttpClient workloadHttpClient,
                                                            KeycloakPrivateClientProperties properties,
                                                            KeycloakIdTokenTrustProperties trust,
                                                            PrivateKeyJwtFactory assertions,
                                                            StrictJoseJson strictJson) {
        try {
            strictJson.checkJson(trust.publicJwk());
            Clock clock = Clock.systemUTC();
            URI endpoint = URI.create(properties.tokenAudience());
            ExternalEndpoint<JsonNode, JsonNode> tokenEndpoint = KeycloakTokenEndpoints.directGrant(endpoint);
            ExternalHttpSettings settings = new ExternalHttpSettings(endpoint.resolve("/"),
                    Duration.ofMillis(properties.requestTimeoutMs()), MAX_TOKEN_RESPONSE_BYTES,
                    Set.of(tokenEndpoint.route()));
            DirectGrantTokenClient transport = new DirectGrantTokenClient(
                    new ExternalHttpClient(workloadHttpClient, settings), tokenEndpoint, assertions, clock);
            KeycloakIdTokenVerifier idTokens = new KeycloakIdTokenVerifier(trust.issuer(),
                    trust.keyId(), JWK.parse(trust.publicJwk()), strictJson, clock);
            return new KeycloakDirectGrantPasswordVerifier(transport, idTokens);
        } catch (IllegalArgumentException | ParseException failure) {
            throw new InvalidKeycloakClientConfigurationException(failure);
        }
    }
}
