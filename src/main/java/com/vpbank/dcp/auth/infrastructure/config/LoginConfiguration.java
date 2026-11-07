package com.vpbank.dcp.auth.infrastructure.config;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.vpbank.dcp.auth.application.port.in.IssueCaptchaUseCase;
import com.vpbank.dcp.auth.application.port.in.LoginUseCase;
import com.vpbank.dcp.auth.application.port.in.UnlockPasswordUseCase;
import com.vpbank.dcp.auth.application.port.out.gateway.AuthorizationTokenGenerator;
import com.vpbank.dcp.auth.application.port.out.gateway.CaptchaGenerator;
import com.vpbank.dcp.auth.application.port.out.gateway.ChallengeSealer;
import com.vpbank.dcp.auth.application.port.out.gateway.CredentialVerifierPort;
import com.vpbank.dcp.auth.application.port.out.gateway.DeviceProofVerifier;
import com.vpbank.dcp.auth.application.port.out.gateway.MfaTransactionPort;
import com.vpbank.dcp.auth.application.port.out.gateway.OpaqueTokenGenerator;
import com.vpbank.dcp.auth.application.port.out.gateway.ServerKeyPairGenerator;
import com.vpbank.dcp.auth.application.port.out.gateway.TokenEnvelopeSealer;
import com.vpbank.dcp.auth.application.port.out.repository.CaptchaStore;
import com.vpbank.dcp.auth.application.port.out.repository.CustomerAuthenticationRepository;
import com.vpbank.dcp.auth.application.port.out.repository.SecurityAuditStore;
import com.vpbank.dcp.auth.application.port.out.repository.EnrollmentRepository;
import com.vpbank.dcp.auth.application.port.out.repository.TransactionStore;
import com.vpbank.dcp.auth.application.port.out.repository.LoginProofReplayStore;
import com.vpbank.dcp.auth.application.port.out.repository.SessionStore;
import com.vpbank.dcp.auth.application.port.out.repository.TrustedDeviceRepository;
import com.vpbank.dcp.auth.application.service.ApprovalRequests;
import com.vpbank.dcp.auth.application.service.ApprovalStatusService;
import com.vpbank.dcp.auth.application.service.ApproveEnrollmentService;
import com.vpbank.dcp.auth.application.service.AuthorizeEnrollmentService;
import com.vpbank.dcp.auth.application.service.CaptchaService;
import com.vpbank.dcp.auth.application.service.ClaimEnrollmentService;
import com.vpbank.dcp.auth.application.service.ConfirmEnrollmentService;
import com.vpbank.dcp.auth.application.service.DeviceManagementService;
import com.vpbank.dcp.auth.application.service.EnrollmentTransactions;
import com.vpbank.dcp.auth.application.service.InitEnrollmentService;
import com.vpbank.dcp.auth.application.service.ListPendingDevicesService;
import com.vpbank.dcp.auth.application.service.LoginService;
import com.vpbank.dcp.auth.application.service.PasswordUnlockService;
import com.vpbank.dcp.auth.application.service.RequestApprovalService;
import com.vpbank.dcp.auth.application.service.SessionManagementService;
import com.vpbank.dcp.auth.application.service.SessionService;
import com.vpbank.dcp.auth.application.service.TrustedDeviceService;
import com.vpbank.dcp.auth.application.service.VerifyEnrollmentService;
import com.vpbank.dcp.auth.domain.model.DevicePolicy;
import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import com.vpbank.dcp.auth.domain.model.EnrollmentPolicy;
import com.vpbank.dcp.auth.domain.model.LockoutPolicy;
import com.vpbank.dcp.auth.domain.model.SessionId;
import com.vpbank.dcp.auth.domain.model.SessionPolicy;
import com.vpbank.dcp.auth.domain.model.TrustedDeviceId;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.AssertionReplayGuard;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.BffAssertionFilter;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.BffAssertionVerifier;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ErrorMessages;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.SessionFilter;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.mapper.DeviceApprovalRestMapper;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.mapper.DeviceRestMapper;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.mapper.LoginRestMapper;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.mapper.PasswordUnlockRestMapper;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.mapper.SessionRestMapper;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.mapper.TrustedDeviceRestMapper;
import com.vpbank.dcp.auth.infrastructure.adapter.out.captcha.AwtCaptchaGenerator;
import com.vpbank.dcp.auth.infrastructure.adapter.out.jose.MlDsaDeviceProofVerifier;
import com.vpbank.dcp.auth.infrastructure.adapter.out.jose.NimbusChallengeSealer;
import com.vpbank.dcp.auth.infrastructure.adapter.out.jose.NimbusServerKeyPairGenerator;
import com.vpbank.dcp.auth.infrastructure.adapter.out.jose.NimbusTokenEnvelopeSealer;
import com.vpbank.dcp.auth.infrastructure.adapter.out.keycloak.KeycloakDirectGrantAdapter;
import com.vpbank.dcp.auth.infrastructure.adapter.out.keycloak.KeycloakIdTokenVerifier;
import com.vpbank.dcp.auth.infrastructure.adapter.out.mfa.HttpMfaTransactionAdapter;
import com.vpbank.dcp.auth.infrastructure.adapter.out.mfa.MfaReceiptVerifier;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.adapter.CustomerAuthenticationPersistenceAdapter;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.CustomerAuthenticationJpaRepository;
import com.vpbank.dcp.auth.infrastructure.adapter.out.token.RandomAuthorizationTokenGenerator;
import com.vpbank.dcp.auth.infrastructure.adapter.out.valkey.LoginProofKeys;
import com.vpbank.dcp.auth.infrastructure.adapter.out.valkey.ValkeyAssertionReplayStore;
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
import org.springframework.data.redis.core.StringRedisTemplate;
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
@EnableConfigurationProperties({LoginProperties.class, MfaProperties.class, BffProperties.class})
public class LoginConfiguration {
    private static final String MFA_RECEIPT_KEY_SETTING = "auth.mfa.receipt-public-jwk";
    private static final String BFF_ASSERTION_KEY_SETTING = "auth.bff.assertion-public-jwk";

    @Bean
    LoginUseCase loginUseCase(CustomerAuthenticationRepository customerAuthenticationRepository,
                              CredentialVerifierPort credentialVerifierPort,
                              CaptchaStore captchaStore,
                              SessionService sessionService,
                              TrustedDeviceService trustedDeviceService,
                              DeviceProofVerifier deviceProofVerifier,
                              LoginProofReplayStore loginProofReplayStore,
                              SecurityAuditStore securityAuditStore,
                              LockoutPolicy lockoutPolicy,
                              LoginProperties properties,
                              Clock clock) {
        return new LoginService(
                customerAuthenticationRepository,
                credentialVerifierPort,
                captchaStore,
                sessionService,
                trustedDeviceService,
                deviceProofVerifier,
                loginProofReplayStore,
                securityAuditStore,
                lockoutPolicy,
                properties.deviceProofRequired(),
                clock);
    }

    /** The login device proof (slice 13): ML-DSA-65 under the key the app sends, verified by the JDK. */
    @Bean
    DeviceProofVerifier deviceProofVerifier(Clock clock) {
        return new MlDsaDeviceProofVerifier(clock);
    }

    /** Used login proof IDs: one SET NX per enforced MOBILE login, in their own key space. */
    @Bean
    LoginProofReplayStore loginProofReplayStore(StringRedisTemplate stringRedisTemplate, Clock clock) {
        ValkeyAssertionReplayStore usedProofIds = new ValkeyAssertionReplayStore(stringRedisTemplate, new LoginProofKeys(), clock);
        return usedProofIds::firstUse;
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

    /** The common device actions (§6.1), exposed by their concrete type; it implements no use case. */
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

    /** The primary enrollment's transactions, shared by init/verify/confirm and by the approval request check. */
    @Bean
    EnrollmentTransactions enrollmentTransactions(TransactionStore transactionStore,
                                                  DevicePolicy devicePolicy,
                                                  Clock clock) {
        // The transaction cannot outlive the restricted session that runs it (slice 11).
        Duration enrollmentLifetime = devicePolicy.restrictedSessionTtl();
        return new EnrollmentTransactions(transactionStore, enrollmentLifetime, clock);
    }

    /** Primary enrollment, step 1: Ksrv and the sealed challenge. */
    @Bean
    InitEnrollmentService initEnrollmentService(EnrollmentTransactions enrollmentTransactions,
                                                TrustedDeviceService trustedDeviceService,
                                                ServerKeyPairGenerator serverKeyPairGenerator,
                                                ChallengeSealer challengeSealer) {
        return new InitEnrollmentService(
                enrollmentTransactions,
                trustedDeviceService,
                serverKeyPairGenerator,
                challengeSealer,
                EnrollmentId::random);
    }

    /** Primary enrollment, step 2: the key proof, then the FACE check. */
    @Bean
    VerifyEnrollmentService verifyEnrollmentService(SessionService sessionService,
                                                    EnrollmentTransactions enrollmentTransactions,
                                                    ChallengeSealer challengeSealer,
                                                    MfaTransactionPort mfaTransactionPort,
                                                    LoginProperties properties) {
        return new VerifyEnrollmentService(
                sessionService,
                enrollmentTransactions,
                challengeSealer,
                mfaTransactionPort,
                enrollmentPolicy(properties));
    }

    /** Primary enrollment, step 3: the FACE outcome and the trust commit. */
    @Bean
    ConfirmEnrollmentService confirmEnrollmentService(SessionService sessionService,
                                                      EnrollmentTransactions enrollmentTransactions,
                                                      TrustedDeviceService trustedDeviceService,
                                                      MfaTransactionPort mfaTransactionPort) {
        return new ConfirmEnrollmentService(
                sessionService,
                enrollmentTransactions,
                trustedDeviceService,
                mfaTransactionPort);
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

    /** The approval flow's requests, shared by its six use cases. */
    @Bean
    ApprovalRequests approvalRequests(EnrollmentRepository enrollmentRepository, Clock clock) {
        return new ApprovalRequests(enrollmentRepository, clock);
    }

    /** Approval by the primary device, the new device's side: ask to be trusted. */
    @Bean
    RequestApprovalService requestApprovalService(ApprovalRequests approvalRequests,
                                                  EnrollmentTransactions enrollmentTransactions,
                                                  TrustedDeviceService trustedDeviceService,
                                                  LoginProperties properties,
                                                  Clock clock) {
        return new RequestApprovalService(
                approvalRequests,
                enrollmentTransactions,
                trustedDeviceService,
                EnrollmentId::random,
                enrollmentPolicy(properties),
                clock);
    }

    /** The new device's side: poll the latest request. */
    @Bean
    ApprovalStatusService approvalStatusService(ApprovalRequests approvalRequests, Clock clock) {
        return new ApprovalStatusService(approvalRequests, clock);
    }

    /** The primary device's side: list the waiting devices. */
    @Bean
    ListPendingDevicesService listPendingDevicesService(TrustedDeviceService trustedDeviceService,
                                                        ApprovalRequests approvalRequests,
                                                        TrustedDeviceRepository trustedDeviceRepository) {
        return new ListPendingDevicesService(trustedDeviceService, approvalRequests, trustedDeviceRepository);
    }

    /** The primary device's side: approve one request (FACE + OTP). */
    @Bean
    ApproveEnrollmentService approveEnrollmentService(TrustedDeviceService trustedDeviceService,
                                                      ApprovalRequests approvalRequests,
                                                      MfaTransactionPort mfaTransactionPort) {
        return new ApproveEnrollmentService(trustedDeviceService, approvalRequests, mfaTransactionPort);
    }

    /** The primary device's side: collect the one-time token after FACE + OTP passed. */
    @Bean
    AuthorizeEnrollmentService authorizeEnrollmentService(TrustedDeviceService trustedDeviceService,
                                                          ApprovalRequests approvalRequests,
                                                          MfaTransactionPort mfaTransactionPort,
                                                          AuthorizationTokenGenerator authorizationTokenGenerator,
                                                          LoginProperties properties,
                                                          Clock clock) {
        return new AuthorizeEnrollmentService(
                trustedDeviceService,
                approvalRequests,
                mfaTransactionPort,
                authorizationTokenGenerator,
                enrollmentPolicy(properties),
                clock);
    }

    /** The new device's side again: claim the token and become trusted. */
    @Bean
    ClaimEnrollmentService claimEnrollmentService(SessionService sessionService,
                                                  ApprovalRequests approvalRequests,
                                                  TrustedDeviceService trustedDeviceService,
                                                  LoginProperties properties,
                                                  Clock clock) {
        return new ClaimEnrollmentService(
                sessionService,
                approvalRequests,
                trustedDeviceService,
                enrollmentPolicy(properties),
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
    MfaTransactionPort mfaTransactionPort(MfaProperties mfaProperties, Clock clock) {
        ECKey mfaReceiptKey = pinnedPublicKey(MFA_RECEIPT_KEY_SETTING, mfaProperties.receiptPublicJwk());
        MfaReceiptVerifier mfaReceiptVerifier =
                new MfaReceiptVerifier(mfaReceiptKey, mfaProperties.receiptIssuer(), clock);

        // The receipt names the customer; the check request says who that must be (slice 11).
        RestClient mfaRestClient =
                RegistrationConfiguration.restClient(mfaProperties.origin(), mfaProperties.timeout());
        return new HttpMfaTransactionAdapter(mfaRestClient, mfaReceiptVerifier);
    }

    /** The startup failure names the setting and never echoes the key material (no cause attached). */
    /** A pinned verification key from a setting; anything but a public P-256 JWK stops startup naming the setting. */
    private static ECKey pinnedPublicKey(String setting, String publicJwk) {
        ECKey pinnedKey;
        try {
            pinnedKey = ECKey.parse(publicJwk);
        } catch (ParseException | IllegalArgumentException | ClassCastException invalid) {
            throw new IllegalStateException(setting + " is not a public EC P-256 JWK");
        }
        if (pinnedKey.isPrivate() || !Curve.P_256.equals(pinnedKey.getCurve())) {
            throw new IllegalStateException(setting + " is not a public EC P-256 JWK");
        }
        return pinnedKey;
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

    /** Device management use cases (list now; revoke, rename and history next). */
    @Bean
    DeviceManagementService deviceManagementService(SessionService sessionService,
                                                    TrustedDeviceService trustedDeviceService) {
        return new DeviceManagementService(sessionService, trustedDeviceService);
    }

    @Bean
    DeviceRestMapper deviceRestMapper(ErrorMessages errorMessages) {
        return new DeviceRestMapper(errorMessages);
    }

    /** Validates the Bearer token's shape only; every use case reads its own session (slice 8). */
    @Bean
    SessionFilter sessionFilter(ErrorMessages errorMessages, LocaleResolver localeResolver) {
        return new SessionFilter(errorMessages, localeResolver);
    }

    /** The BFF's assertion key is pinned; its key ID must be in the JWK because the header has to name it. */
    @Bean
    BffAssertionVerifier bffAssertionVerifier(BffProperties bffProperties, Clock clock) {
        ECKey bffAssertionKey = pinnedPublicKey(BFF_ASSERTION_KEY_SETTING, bffProperties.assertionPublicJwk());
        if (bffAssertionKey.getKeyID() == null) {
            throw new IllegalStateException(BFF_ASSERTION_KEY_SETTING + " has no kid");
        }
        return new BffAssertionVerifier(bffAssertionKey, bffProperties.assertionIssuer(), clock);
    }

    /** Admits the trusted-device routes from a BFF assertion, each assertion once (slice 11). */
    @Bean
    BffAssertionFilter bffAssertionFilter(BffAssertionVerifier bffAssertionVerifier,
                                          ValkeyAssertionReplayStore valkeyAssertionReplayStore,
                                          ErrorMessages errorMessages,
                                          LocaleResolver localeResolver) {
        AssertionReplayGuard assertionReplayGuard = valkeyAssertionReplayStore::firstUse;
        return new BffAssertionFilter(bffAssertionVerifier, assertionReplayGuard, errorMessages, localeResolver);
    }
}
