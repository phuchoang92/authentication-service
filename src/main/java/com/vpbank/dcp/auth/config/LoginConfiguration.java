package com.vpbank.dcp.auth.config;

import com.vpbank.dcp.auth.adapter.in.web.common.ErrorMessages;
import com.vpbank.dcp.auth.adapter.in.web.common.SessionFilter;
import com.vpbank.dcp.auth.adapter.in.web.mapper.LoginWebMapper;
import com.vpbank.dcp.auth.adapter.in.web.mapper.PasswordUnlockWebMapper;
import com.vpbank.dcp.auth.adapter.out.captcha.AwtCaptchaGenerator;
import com.vpbank.dcp.auth.adapter.in.web.mapper.SessionWebMapper;
import com.vpbank.dcp.auth.adapter.out.jose.NimbusTokenEnvelopeSealer;
import com.vpbank.dcp.auth.adapter.out.keycloak.KeycloakDirectGrantAdapter;
import com.vpbank.dcp.auth.adapter.out.keycloak.KeycloakIdTokenVerifier;
import com.vpbank.dcp.auth.adapter.out.persistence.adapter.CustomerAuthenticationPersistenceAdapter;
import com.vpbank.dcp.auth.adapter.out.persistence.repository.CustomerAuthenticationJpaRepository;
import com.vpbank.dcp.auth.application.port.in.CurrentSessionUseCase;
import com.vpbank.dcp.auth.application.port.in.IssueCaptchaUseCase;
import com.vpbank.dcp.auth.application.port.in.LoginUseCase;
import com.vpbank.dcp.auth.application.port.in.UnlockPasswordUseCase;
import com.vpbank.dcp.auth.application.port.out.CaptchaGenerator;
import com.vpbank.dcp.auth.application.port.out.CaptchaStore;
import com.vpbank.dcp.auth.application.port.out.CredentialVerifierPort;
import com.vpbank.dcp.auth.application.port.out.CustomerAuthenticationRepository;
import com.vpbank.dcp.auth.application.port.out.OpaqueTokenGenerator;
import com.vpbank.dcp.auth.application.port.out.SessionStore;
import com.vpbank.dcp.auth.application.port.out.TokenEnvelopeSealer;
import com.vpbank.dcp.auth.application.port.out.TrustedDeviceRepository;
import com.vpbank.dcp.auth.application.service.CaptchaService;
import com.vpbank.dcp.auth.application.service.LoginService;
import com.vpbank.dcp.auth.application.service.PasswordUnlockService;
import com.vpbank.dcp.auth.application.service.SessionService;
import com.vpbank.dcp.auth.application.service.TrustedDeviceService;
import com.vpbank.dcp.auth.domain.model.DevicePolicy;
import com.vpbank.dcp.auth.domain.model.LockoutPolicy;
import com.vpbank.dcp.auth.domain.model.TrustedDeviceId;
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
                              CaptchaStore captchas, SessionStore sessions, TokenEnvelopeSealer sealer,
                              OpaqueTokenGenerator tokens, TrustedDeviceService trustedDevices, SessionPolicy policy,
                              LockoutPolicy lockoutPolicy, DevicePolicy devicePolicy, Clock clock) {
        return new LoginService(identities, credentials, captchas, sessions, sealer, tokens, SessionId::random,
                trustedDevices, policy, lockoutPolicy, devicePolicy, clock);
    }

    /**
     * Exposed by its concrete type: LoginService depends on it directly (§6.1), while the controller
     * is injected by the ListDevicesUseCase interface it implements (one bean, two views).
     */
    @Bean
    TrustedDeviceService trustedDeviceService(TrustedDeviceRepository devices, DevicePolicy devicePolicy, Clock clock) {
        return new TrustedDeviceService(devices, devicePolicy, TrustedDeviceId::random, clock);
    }


    @Bean
    IssueCaptchaUseCase issueCaptchaUseCase(CustomerAuthenticationRepository identities, CaptchaGenerator generator,
                                            CaptchaStore captchas, LoginProperties properties, Clock clock) {
        return new CaptchaService(identities, generator, captchas, properties.lockout().captchaLifetime(), clock);
    }

    @Bean
    UnlockPasswordUseCase unlockPasswordUseCase(CustomerAuthenticationRepository identities) {
        return new PasswordUnlockService(identities);
    }

    @Bean
    PasswordUnlockWebMapper passwordUnlockWebMapper(ErrorMessages errors) {
        return new PasswordUnlockWebMapper(errors);
    }

    @Bean
    CaptchaGenerator captchaGenerator() {
        return new AwtCaptchaGenerator(new java.security.SecureRandom());
    }

    @Bean
    LockoutPolicy lockoutPolicy(LoginProperties properties) {
        LoginProperties.Lockout lockout = properties.lockout();
        return new LockoutPolicy(lockout.captchaAfter(), new java.util.TreeMap<>(lockout.temporaryLocksOrDefault()),
                lockout.permanentAt());
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
