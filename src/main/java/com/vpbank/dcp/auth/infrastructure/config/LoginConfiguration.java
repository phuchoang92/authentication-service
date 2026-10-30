package com.vpbank.dcp.auth.infrastructure.config;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.vpbank.dcp.auth.application.port.in.CurrentSessionUseCase;
import com.vpbank.dcp.auth.application.port.in.IssueCaptchaUseCase;
import com.vpbank.dcp.auth.application.port.in.LoginUseCase;
import com.vpbank.dcp.auth.application.port.in.UnlockPasswordUseCase;
import com.vpbank.dcp.auth.application.port.out.gateway.AuthorizationTokenGenerator;
import com.vpbank.dcp.auth.application.port.out.gateway.CaptchaGenerator;
import com.vpbank.dcp.auth.application.port.out.gateway.ChallengeSealer;
import com.vpbank.dcp.auth.application.port.out.gateway.CredentialVerifierPort;
import com.vpbank.dcp.auth.application.port.out.gateway.MfaTransactionPort;
import com.vpbank.dcp.auth.application.port.out.gateway.OpaqueTokenGenerator;
import com.vpbank.dcp.auth.application.port.out.gateway.ServerKeyPairGenerator;
import com.vpbank.dcp.auth.application.port.out.gateway.TokenEnvelopeSealer;
import com.vpbank.dcp.auth.application.port.out.repository.CaptchaStore;
import com.vpbank.dcp.auth.application.port.out.repository.CustomerAuthenticationRepository;
import com.vpbank.dcp.auth.application.port.out.repository.EnrollmentRepository;
import com.vpbank.dcp.auth.application.port.out.repository.SessionStore;
import com.vpbank.dcp.auth.application.port.out.repository.TrustedDeviceRepository;
import com.vpbank.dcp.auth.application.service.CaptchaService;
import com.vpbank.dcp.auth.application.service.DeviceApprovalService;
import com.vpbank.dcp.auth.application.service.DeviceEnrollmentService;
import com.vpbank.dcp.auth.application.service.LoginService;
import com.vpbank.dcp.auth.application.service.PasswordUnlockService;
import com.vpbank.dcp.auth.application.service.SessionManagementService;
import com.vpbank.dcp.auth.application.service.SessionService;
import com.vpbank.dcp.auth.application.service.TrustedDeviceService;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DevicePolicy;
import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import com.vpbank.dcp.auth.domain.model.EnrollmentPolicy;
import com.vpbank.dcp.auth.domain.model.LockoutPolicy;
import com.vpbank.dcp.auth.domain.model.SessionId;
import com.vpbank.dcp.auth.domain.model.SessionPolicy;
import com.vpbank.dcp.auth.domain.model.TrustedDeviceId;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ErrorMessages;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.SessionFilter;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.mapper.DeviceApprovalRestMapper;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.mapper.LoginRestMapper;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.mapper.PasswordUnlockRestMapper;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.mapper.SessionRestMapper;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.mapper.TrustedDeviceRestMapper;
import com.vpbank.dcp.auth.infrastructure.adapter.out.captcha.AwtCaptchaGenerator;
import com.vpbank.dcp.auth.infrastructure.adapter.out.jose.NimbusChallengeSealer;
import com.vpbank.dcp.auth.infrastructure.adapter.out.jose.NimbusServerKeyPairGenerator;
import com.vpbank.dcp.auth.infrastructure.adapter.out.jose.NimbusTokenEnvelopeSealer;
import com.vpbank.dcp.auth.infrastructure.adapter.out.keycloak.KeycloakDirectGrantAdapter;
import com.vpbank.dcp.auth.infrastructure.adapter.out.keycloak.KeycloakIdTokenVerifier;
import com.vpbank.dcp.auth.infrastructure.adapter.out.mfa.HttpMfaTransactionAdapter;
import com.vpbank.dcp.auth.infrastructure.adapter.out.mfa.MfaReceiptVerifier;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.adapter.CustomerAuthenticationPersistenceAdapter;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.CustomerAuthenticationJpaRepository;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.DeviceEnrollmentJpaRepository;
import com.vpbank.dcp.auth.infrastructure.adapter.out.token.RandomAuthorizationTokenGenerator;
import java.security.SecureRandom;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.util.SortedMap;
import java.util.TreeMap;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestClient;
import org.springframework.web.servlet.LocaleResolver;

/**
 * Login, logout and extend (slice 2), off by default. The whole object graph of the capability
 * is here; the session store and policy come from {@link ValkeyConfiguration}. {@link SessionService} holds
 * the common session actions and {@link SessionManagementService} the three session use cases; controllers see
 * the interfaces.
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(prefix = "auth.login", name = "enabled", havingValue = "true")
@EnableConfigurationProperties({LoginProperties.class, MfaProperties.class})
public class LoginConfiguration {
    private static final String MFA_RECEIPT_KEY_SETTING = "auth.mfa.receipt-public-jwk";

    @Bean
    LoginUseCase loginUseCase(CustomerAuthenticationRepository customerAuthenticationRepository,
                              CredentialVerifierPort credentialVerifierPort,
                              CaptchaStore captchaStore,
                              SessionService sessionService,
                              TrustedDeviceService trustedDeviceService,
                              LockoutPolicy lockoutPolicy,
                              Clock clock) {
        return new LoginService(
                customerAuthenticationRepository,
                credentialVerifierPort,
                captchaStore,
                sessionService,
                trustedDeviceService,
                lockoutPolicy,
                clock);
    }

    /**
     * The common session actions (§6.1), exposed by their concrete type: Login, the trust flows and the
     * session use cases compose them; it implements no use case itself.
     */
    @Bean
    SessionService sessionService(SessionStore sessionStore,
                                  TokenEnvelopeSealer tokenEnvelopeSealer,
                                  OpaqueTokenGenerator opaqueTokenGenerator,
                                  SessionPolicy sessionPolicy,
                                  DevicePolicy devicePolicy,
                                  Clock clock) {
        return new SessionService(
                sessionStore,
                tokenEnvelopeSealer,
                opaqueTokenGenerator,
                SessionId::random,
                sessionPolicy,
                devicePolicy,
                clock);
    }

    /** One bean, three use-case views (resolve / extend / logout). */
    @Bean
    SessionManagementService sessionManagementService(SessionService sessionService) {
        return new SessionManagementService(sessionService);
    }

    /**
     * Exposed by its concrete type: LoginService depends on it directly (§6.1), while the controller
     * is injected by the ListDevicesUseCase interface it implements (one bean, two views).
     */
    @Bean
    TrustedDeviceService trustedDeviceService(TrustedDeviceRepository trustedDeviceRepository,
                                              DevicePolicy devicePolicy,
                                              Clock clock) {
        return new TrustedDeviceService(trustedDeviceRepository, devicePolicy, TrustedDeviceId::random, clock);
    }

    @Bean
    IssueCaptchaUseCase issueCaptchaUseCase(CustomerAuthenticationRepository customerAuthenticationRepository,
                                            CaptchaGenerator captchaGenerator,
                                            CaptchaStore captchaStore,
                                            LoginProperties properties,
                                            Clock clock) {
        Duration captchaLifetime = properties.lockout().captchaLifetime();
        return new CaptchaService(
                customerAuthenticationRepository,
                captchaGenerator,
                captchaStore,
                captchaLifetime,
                clock);
    }

    @Bean
    UnlockPasswordUseCase unlockPasswordUseCase(CustomerAuthenticationRepository customerAuthenticationRepository) {
        return new PasswordUnlockService(customerAuthenticationRepository);
    }

    @Bean
    PasswordUnlockRestMapper passwordUnlockRestMapper(ErrorMessages errorMessages) {
        return new PasswordUnlockRestMapper(errorMessages);
    }

    /** One bean, three use-case views (init/verify/confirm), like SessionService. */
    @Bean
    DeviceEnrollmentService deviceEnrollmentService(SessionService sessionService,
                                                    EnrollmentRepository enrollmentRepository,
                                                    TrustedDeviceService trustedDeviceService,
                                                    MfaTransactionPort mfaTransactionPort,
                                                    ServerKeyPairGenerator serverKeyPairGenerator,
                                                    ChallengeSealer challengeSealer,
                                                    LoginProperties properties,
                                                    Clock clock) {
        EnrollmentPolicy enrollmentPolicy = enrollmentPolicy(properties);
        return new DeviceEnrollmentService(
                sessionService,
                enrollmentRepository,
                trustedDeviceService,
                mfaTransactionPort,
                serverKeyPairGenerator,
                challengeSealer,
                EnrollmentId::random,
                enrollmentPolicy,
                clock);
    }

    /** Policy bounds are the domain's; a bad setting stops the application with the record's message. */
    private static EnrollmentPolicy enrollmentPolicy(LoginProperties properties) {
        LoginProperties.Approval approval = properties.approval();
        return new EnrollmentPolicy(
                properties.enrollmentMaxVerifyAttempts(),
                approval.pendingWindow(),
                approval.tokenLifetime(),
                approval.maxClaimAttempts(),
                approval.maxPendingDevices());
    }

    /** One bean, six use-case views (request/status/pending/approve/authorize/claim), like DeviceEnrollmentService. */
    @Bean
    DeviceApprovalService deviceApprovalService(SessionService sessionService,
                                                EnrollmentRepository enrollmentRepository,
                                                TrustedDeviceRepository trustedDeviceRepository,
                                                TrustedDeviceService trustedDeviceService,
                                                MfaTransactionPort mfaTransactionPort,
                                                AuthorizationTokenGenerator authorizationTokenGenerator,
                                                LoginProperties properties,
                                                Clock clock) {
        EnrollmentPolicy enrollmentPolicy = enrollmentPolicy(properties);
        return new DeviceApprovalService(
                sessionService,
                enrollmentRepository,
                trustedDeviceRepository,
                trustedDeviceService,
                mfaTransactionPort,
                authorizationTokenGenerator,
                EnrollmentId::random,
                enrollmentPolicy,
                clock);
    }

    @Bean
    AuthorizationTokenGenerator authorizationTokenGenerator() {
        return new RandomAuthorizationTokenGenerator(new SecureRandom());
    }

    @Bean
    DeviceApprovalRestMapper deviceApprovalRestMapper(ErrorMessages errorMessages) {
        return new DeviceApprovalRestMapper(errorMessages);
    }

    @Bean
    ServerKeyPairGenerator serverKeyPairGenerator() {
        return new NimbusServerKeyPairGenerator();
    }

    @Bean
    ChallengeSealer challengeSealer() {
        return new NimbusChallengeSealer(new SecureRandom());
    }

    @Bean
    MfaTransactionPort mfaTransactionPort(MfaProperties mfaProperties,
                                          DeviceEnrollmentJpaRepository deviceEnrollmentJpaRepository,
                                          Clock clock) {
        ECKey mfaReceiptKey = pinnedReceiptKey(mfaProperties.receiptPublicJwk());
        MfaReceiptVerifier mfaReceiptVerifier =
                new MfaReceiptVerifier(mfaReceiptKey, mfaProperties.receiptIssuer(), clock);

        // The receipt names the customer; the enrollment row is the only place that says who that must be.
        HttpMfaTransactionAdapter.CustomerLookup enrollmentCustomerLookup = (EnrollmentId enrollmentId) ->
                deviceEnrollmentJpaRepository.findById(enrollmentId.value())
                        .map(enrollmentEntity -> new CustomerId(enrollmentEntity.getCustomerId()))
                        .orElseThrow(() -> new IllegalStateException("Unknown enrollment " + enrollmentId));

        RestClient mfaRestClient =
                RegistrationConfiguration.restClient(mfaProperties.origin(), mfaProperties.timeout());
        return new HttpMfaTransactionAdapter(mfaRestClient, mfaReceiptVerifier, enrollmentCustomerLookup);
    }

    /** The startup failure names the setting and never echoes the key material (no cause attached). */
    private static ECKey pinnedReceiptKey(String receiptPublicJwk) {
        ECKey receiptKey;
        try {
            receiptKey = ECKey.parse(receiptPublicJwk);
        } catch (ParseException | IllegalArgumentException | ClassCastException invalid) {
            throw new IllegalStateException(MFA_RECEIPT_KEY_SETTING + " is not a public EC P-256 JWK");
        }
        if (receiptKey.isPrivate() || !Curve.P_256.equals(receiptKey.getCurve())) {
            throw new IllegalStateException(MFA_RECEIPT_KEY_SETTING + " is not a public EC P-256 JWK");
        }
        return receiptKey;
    }

    @Bean
    CaptchaGenerator captchaGenerator() {
        return new AwtCaptchaGenerator(new SecureRandom());
    }

    @Bean
    LockoutPolicy lockoutPolicy(LoginProperties properties) {
        LoginProperties.Lockout lockout = properties.lockout();
        SortedMap<Integer, Duration> temporaryLocks = new TreeMap<>(lockout.temporaryLocksOrDefault());
        return new LockoutPolicy(lockout.captchaAfter(), temporaryLocks, lockout.permanentAt());
    }


    @Bean
    CustomerAuthenticationRepository customerAuthenticationRepository(
            CustomerAuthenticationJpaRepository customerAuthenticationJpaRepository) {
        return new CustomerAuthenticationPersistenceAdapter(customerAuthenticationJpaRepository);
    }

    @Bean
    CredentialVerifierPort credentialVerifierPort(LoginProperties properties, Clock clock) {
        LoginProperties.Keycloak keycloak = properties.keycloak();
        RestClient keycloakRestClient = RegistrationConfiguration.restClient(keycloak.baseUrl(), keycloak.timeout());

        KeycloakIdTokenVerifier keycloakIdTokenVerifier = new KeycloakIdTokenVerifier(
                keycloakRestClient,
                keycloak.realm(),
                keycloak.issuer(),
                keycloak.clientId(),
                clock);

        return new KeycloakDirectGrantAdapter(
                keycloakRestClient,
                keycloak.realm(),
                keycloak.issuer(),
                keycloak.clientId(),
                keycloak.clientSecret(),
                keycloakIdTokenVerifier);
    }

    @Bean
    TokenEnvelopeSealer tokenEnvelopeSealer() {
        return new NimbusTokenEnvelopeSealer();
    }

    @Bean
    LoginRestMapper loginRestMapper(ErrorMessages errorMessages) {
        return new LoginRestMapper(errorMessages);
    }

    @Bean
    SessionRestMapper sessionRestMapper(ErrorMessages errorMessages) {
        return new SessionRestMapper(errorMessages);
    }

    @Bean
    TrustedDeviceRestMapper trustedDeviceRestMapper(ErrorMessages errorMessages) {
        return new TrustedDeviceRestMapper(errorMessages);
    }

    @Bean
    SessionFilter sessionFilter(CurrentSessionUseCase currentSessionUseCase,
                                ErrorMessages errorMessages,
                                LocaleResolver localeResolver) {
        return new SessionFilter(currentSessionUseCase, errorMessages, localeResolver);
    }
}
