package com.vpbank.dcp.auth.config;

import com.vpbank.dcp.auth.adapter.in.web.common.ErrorMessages;
import com.vpbank.dcp.auth.adapter.in.web.common.SessionFilter;
import com.vpbank.dcp.auth.adapter.in.web.mapper.LoginWebMapper;
import com.vpbank.dcp.auth.adapter.in.web.mapper.SessionWebMapper;
import com.vpbank.dcp.auth.adapter.out.jose.NimbusTokenEnvelopeSealer;
import com.vpbank.dcp.auth.adapter.out.keycloak.KeycloakDirectGrantAdapter;
import com.vpbank.dcp.auth.adapter.out.keycloak.KeycloakIdTokenVerifier;
import com.vpbank.dcp.auth.adapter.out.persistence.adapter.CustomerAuthenticationPersistenceAdapter;
import com.vpbank.dcp.auth.adapter.out.persistence.repository.CustomerAuthenticationJpaRepository;
import com.vpbank.dcp.auth.application.port.in.CurrentSessionUseCase;
import com.vpbank.dcp.auth.application.port.in.LoginUseCase;
import com.vpbank.dcp.auth.application.port.out.CredentialVerifierPort;
import com.vpbank.dcp.auth.application.port.out.CustomerAuthenticationRepository;
import com.vpbank.dcp.auth.application.port.out.OpaqueTokenGenerator;
import com.vpbank.dcp.auth.application.port.out.SessionStore;
import com.vpbank.dcp.auth.application.port.out.TokenEnvelopeSealer;
import com.vpbank.dcp.auth.application.service.LoginService;
import com.vpbank.dcp.auth.application.service.SessionService;
import com.vpbank.dcp.auth.domain.model.SessionId;
import com.vpbank.dcp.auth.domain.model.SessionPolicy;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestClient;
import org.springframework.web.servlet.LocaleResolver;

import java.time.Clock;

/**
 * Login, logout and extend (slice 2), off by default. The whole object graph of the capability
 * is here; the session store and policy come from {@link ValkeyConfiguration}. {@link SessionService}
 * is exposed by its concrete type (it implements three use cases); controllers see the interfaces.
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(prefix = "auth.login", name = "enabled", havingValue = "true")
@EnableConfigurationProperties(LoginProperties.class)
public class LoginConfiguration {

    @Bean
    LoginUseCase loginUseCase(CustomerAuthenticationRepository identities, CredentialVerifierPort credentials,
                              SessionStore sessions, TokenEnvelopeSealer sealer, OpaqueTokenGenerator tokens,
                              SessionPolicy policy, Clock clock) {
        return new LoginService(identities, credentials, sessions, sealer, tokens, SessionId::random, policy, clock);
    }

    @Bean
    SessionService sessionService(SessionStore sessions, SessionPolicy policy, Clock clock) {
        return new SessionService(sessions, policy, clock);
    }

    @Bean
    CustomerAuthenticationRepository customerAuthenticationRepository(CustomerAuthenticationJpaRepository rows) {
        return new CustomerAuthenticationPersistenceAdapter(rows);
    }

    @Bean
    CredentialVerifierPort credentialVerifierPort(LoginProperties properties, Clock clock) {
        LoginProperties.Keycloak keycloak = properties.keycloak();
        RestClient client = RegistrationConfiguration.restClient(keycloak.baseUrl(), keycloak.timeout());
        return new KeycloakDirectGrantAdapter(client, keycloak.realm(), keycloak.issuer(), keycloak.clientId(),
                keycloak.clientSecret(), new KeycloakIdTokenVerifier(client, keycloak.realm(), keycloak.issuer(),
                keycloak.clientId(), clock));
    }

    @Bean
    TokenEnvelopeSealer tokenEnvelopeSealer() {
        return new NimbusTokenEnvelopeSealer();
    }

    @Bean
    LoginWebMapper loginWebMapper(ErrorMessages errors) {
        return new LoginWebMapper(errors);
    }

    @Bean
    SessionWebMapper sessionWebMapper(ErrorMessages errors) {
        return new SessionWebMapper(errors);
    }

    @Bean
    SessionFilter sessionFilter(CurrentSessionUseCase sessions, ErrorMessages errors, LocaleResolver locales) {
        return new SessionFilter(sessions, errors, locales);
    }
}
