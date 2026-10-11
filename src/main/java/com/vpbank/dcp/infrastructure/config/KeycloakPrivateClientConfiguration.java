package com.vpbank.dcp.infrastructure.config;

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.vpbank.dcp.core.port.out.keycloak.DirectGrantPasswordVerifier;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.StrictJoseJson;
import com.vpbank.dcp.infrastructure.adapter.out.keycloak.DirectGrantTokenClient;
import com.vpbank.dcp.infrastructure.adapter.out.keycloak.HttpDirectGrantPasswordVerifier;
import com.vpbank.dcp.infrastructure.adapter.out.keycloak.InvalidKeycloakClientConfigurationException;
import com.vpbank.dcp.infrastructure.adapter.out.keycloak.KeycloakIdTokenVerifier;
import com.vpbank.dcp.infrastructure.adapter.out.keycloak.PrivateKeyJwtFactory;
import com.vpbank.dcp.infrastructure.config.properties.KeycloakIdTokenTrustProperties;
import com.vpbank.dcp.infrastructure.config.properties.KeycloakPrivateClientProperties;
import java.net.URI;
import java.net.http.HttpClient;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import tools.jackson.databind.json.JsonMapper;

@Configuration(proxyBeanMethods = false)
@ConditionalOnWebApplication
@EnableConfigurationProperties({KeycloakPrivateClientProperties.class, KeycloakIdTokenTrustProperties.class})
public class KeycloakPrivateClientConfiguration {

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
                                                             StrictJoseJson strictJson,
                                                             JsonMapper json) {
        try {
            strictJson.checkJson(trust.publicJwk());
            Clock clock = Clock.systemUTC();
            DirectGrantTokenClient transport = new DirectGrantTokenClient(workloadHttpClient,
                    URI.create(properties.tokenAudience()), assertions,
                    Duration.ofMillis(properties.requestTimeoutMs()), clock);
            KeycloakIdTokenVerifier idTokens = new KeycloakIdTokenVerifier(trust.issuer(),
                    trust.keyId(), JWK.parse(trust.publicJwk()), strictJson, clock);
            return new HttpDirectGrantPasswordVerifier(transport, idTokens, strictJson, json);
        } catch (IllegalArgumentException | ParseException failure) {
            throw new InvalidKeycloakClientConfigurationException(failure);
        }
    }
}
