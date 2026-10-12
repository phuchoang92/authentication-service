package com.vpbank.dcp.infrastructure.config;

import com.nimbusds.jose.jwk.ECKey;
import com.vpbank.dcp.core.application.password.*;
import com.vpbank.dcp.core.application.session.BankingRequestAdmissionService;
import com.vpbank.dcp.core.domain.device.TrustedDeviceRouting;
import com.vpbank.dcp.core.domain.security.LookupKeyVersion;
import com.vpbank.dcp.core.port.in.password.PasswordLoginUseCase;
import com.vpbank.dcp.core.port.in.session.BankingRequestAdmissionUseCase;
import com.vpbank.dcp.core.port.out.customer.CustomerDirectory;
import com.vpbank.dcp.core.port.out.customer.CustomerOwnerStore;
import com.vpbank.dcp.core.port.out.keycloak.DirectGrantPasswordVerifier;
import com.vpbank.dcp.core.port.out.password.*;
import com.vpbank.dcp.core.port.out.session.*;
import com.vpbank.dcp.infrastructure.adapter.in.web.ExternalUriPolicy;
import com.vpbank.dcp.infrastructure.adapter.in.web.password.PasswordLoginRequestMapper;
import com.vpbank.dcp.infrastructure.adapter.in.web.password.PasswordLoginResponseMapper;
import com.vpbank.dcp.infrastructure.adapter.in.web.session.BankingRequestAdmissionRequestMapper;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.*;
import com.vpbank.dcp.infrastructure.adapter.out.persistence.session.JpaPasswordSessionStore;
import com.vpbank.dcp.infrastructure.adapter.out.persistence.session.PasswordSessionRepository;
import com.vpbank.dcp.infrastructure.adapter.out.redis.RedisBankingSessionAdmissionStore;
import com.vpbank.dcp.infrastructure.adapter.out.redis.RedisPasswordSessionAuthority;
import com.vpbank.dcp.infrastructure.adapter.out.redis.RedisServerIdentity;
import com.vpbank.dcp.infrastructure.adapter.out.redis.VerifiedAuthorityScript;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.AuthorityScope;
import com.vpbank.dcp.infrastructure.config.properties.CustomerContextSigningProperties;
import com.vpbank.dcp.infrastructure.config.properties.NativeSessionProperties;
import com.vpbank.dcp.infrastructure.config.properties.PasswordFlowProperties;
import jakarta.persistence.EntityManager;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.transaction.support.TransactionTemplate;
import tools.jackson.databind.json.JsonMapper;

import java.security.SecureRandom;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;

/**
 * Assembles focused use cases; integration activation cannot be enabled in production.
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnWebApplication
@EnableConfigurationProperties({PasswordFlowProperties.class, NativeSessionProperties.class,
        CustomerContextSigningProperties.class})
public class PasswordFlowConfiguration {
    private static final String APPLY_SHA256 =
            "429bd544ac3517e4584ff0c7e42ff8c4dff71ef33a1605e23b8725a935b1fdd2";
    private static final String DELIVER_SHA256 =
            "55305f7da8345d32d39b0dcee8e7917cbccfaa64f808dc482bbfb95f19123979";

    @Bean
    Clock authenticationClock() {
        return Clock.systemUTC();
    }

    @Bean
    PasswordLoginRequestMapper passwordLoginRequestMapper(ExternalUriPolicy uri,
                                                              PasswordFlowProperties policy,
                                                              JsonMapper json, Clock clock) {
        return new PasswordLoginRequestMapper(uri, policy, json, clock);
    }

    @Bean
    PasswordLoginResponseMapper passwordLoginResponseMapper(Clock clock) {
        return new PasswordLoginResponseMapper(clock);
    }

    @Bean
    BankingRequestAdmissionRequestMapper bankingRequestAdmissionRequestMapper(ExternalUriPolicy uri) {
        return new BankingRequestAdmissionRequestMapper(uri);
    }

    @Bean
    PasswordAvailabilityPolicy passwordAvailability(NativeSessionProperties properties,
                                                    Environment environment) {
        if (properties.integrationActivationEnabled()
                && !environment.acceptsProfiles(Profiles.of("integration"))) {
            throw new InvalidPasswordRuntimeConfigurationException();
        }
        return new PasswordAvailabilityPolicy(properties.integrationActivationEnabled());
    }

    @Bean
    PasswordCommandHasher passwordCommandHasher(PasswordFlowProperties properties,
                                                LengthPrefixedSigningInputEncoder encoding) {
        return new PasswordCommandHmac(properties.commandKeyId(),
                Map.of(properties.commandKeyId(), secret(properties.commandHmacBase64())), encoding);
    }

    @Bean
    CheckCustomerLoginEligibilityService checkCustomerLoginEligibility(CustomerDirectory customers,
                                                       PasswordFlowProperties properties) {
        return new CheckCustomerLoginEligibilityService(customers,
                Duration.ofMillis(properties.customerStatusMaxAgeMs()));
    }

    @Bean
    ConfirmPasswordLoginOwnerService confirmPasswordLoginOwner(CheckCustomerLoginEligibilityService snapshots,
                                                 CustomerOwnerStore owners,
                                                 PasswordFlowProperties properties) {
        return new ConfirmPasswordLoginOwnerService(snapshots, owners,
                properties.customerPolicyVersion());
    }

    @Bean
    ReservePasswordLoginService reservePasswordLogin(PasswordDeviceKeyStore keys,
                                               PasswordProofVerifier proofs,
                                               PasswordProofReplay replay,
                                               PasswordCommandHasher commands,
                                               PasswordOperationStore operations) {
        return new ReservePasswordLoginService(keys, proofs, replay, commands, operations);
    }

    @Bean
    VerifyPasswordLoginIdentityService verifyPasswordLoginIdentity(ReservePasswordLoginService admission,
                                                       PasswordOperationStore operations,
                                                       DirectGrantPasswordVerifier keycloak,
                                                       ConfirmPasswordLoginOwnerService customers,
                                                       Clock clock) {
        return new VerifyPasswordLoginIdentityService(admission, operations, keycloak, customers, clock);
    }

    @Bean
    PasswordLoginRouteService passwordRoutes(VerifyPasswordLoginIdentityService credentials,
                                             PasswordDeviceRouteStore deviceRoutes,
                                             PasswordOperationStore operations) {
        return new PasswordLoginRouteService(credentials,
                new ResolveTrustedDeviceRouteService(deviceRoutes, new TrustedDeviceRouting()), operations);
    }

    @Bean
    LookupKeyVersion bankingLookupKeyVersion(NativeSessionProperties properties) {
        return new LookupKeyVersion(properties.lookupKeyVersion());
    }

    @Bean
    TokenLookupHasher bankingTokenLookupHasher(LookupKeyVersion version,
                                               NativeSessionProperties properties) {
        return new TokenLookupHasher(version, secret(properties.lookupHmacBase64()));
    }

    @Bean
    SecureRandom authenticationRandom() {
        return new SecureRandom();
    }

    @Bean
    PasswordSessionCryptography passwordSessionCryptography(NativeSessionProperties properties,
                                                            BankingTokenEnvelopeIssuer envelopes,
                                                            LengthPrefixedSigningInputEncoder encoding,
                                                            Sha256Digests digests,
                                                            LookupKeyVersion version,
                                                            TokenLookupHasher lookup,
                                                            SecureRandom random) {
        return new PasswordSessionCryptoAdapter(new BankingTokenIssuer(version, random),
                lookup, envelopes, version, encoding, digests, random);
    }

    @Bean
    PasswordSessionRepository passwordSessionRepository(EntityManager sql, JsonMapper json,
                                                        PasswordFlowProperties properties) {
        return new PasswordSessionRepository(sql, json,
                Duration.ofMillis(properties.customerStatusMaxAgeMs()));
    }

    @Bean
    PasswordSessionStore passwordSessionStore(PasswordSessionRepository repository,
                                              TransactionTemplate transactions, Clock clock) {
        return new JpaPasswordSessionStore(repository, transactions, clock);
    }

    @Bean
    PasswordSessionAuthority passwordSessionAuthority(StringRedisTemplate redis,
                                                      RedisServerIdentity identity,
                                                      AuthorityScope scope,
                                                      NativeSessionProperties properties,
                                                      Clock clock) {
        return new RedisPasswordSessionAuthority(redis, identity, scope,
                VerifiedAuthorityScript.load("redis/password_session_apply.lua", APPLY_SHA256),
                VerifiedAuthorityScript.load("redis/password_session_deliver.lua", DELIVER_SHA256),
                properties.customerFeedSource(),
                Duration.ofMillis(properties.nonceValidityMs()), clock);
    }

    @Bean
    ActivatePasswordSessionService activatePasswordSession(PasswordSessionStore store,
                                            PasswordSessionCryptography cryptography,
                                            PasswordSessionAuthority authority, Clock clock) {
        return new ActivatePasswordSessionService(store, cryptography, authority, clock);
    }

    @Bean
    SessionProofVerifier sessionProofVerifier(DpopProofVerifier dpop, Sha256Digests digests) {
        return new DpopSessionProofVerifier(dpop, digests);
    }

    @Bean
    CustomerContextSigner customerContextSigner(CustomerContextSigningProperties properties,
                                                Clock clock) {
        try {
            return new JwtCustomerContextSigner(properties.issuer(),
                    ECKey.parse(properties.privateJwk()), clock);
        } catch (ParseException | IllegalArgumentException failure) {
            throw new InvalidPasswordRuntimeConfigurationException(failure);
        }
    }

    @Bean
    BankingSessionAdmissionStore bankingSessionAdmissionStore(StringRedisTemplate redis,
                                                              RedisServerIdentity identity,
                                                              TokenLookupHasher lookup,
                                                              LookupKeyVersion version,
                                                              AuthorityScope scope,
                                                              NativeSessionProperties properties,
                                                              SecureRandom random) {
        return new RedisBankingSessionAdmissionStore(redis, identity, lookup, version, scope,
                VerifiedAuthorityScript.load("redis/password_session_deliver.lua", DELIVER_SHA256),
                properties.customerFeedSource(), Duration.ofMillis(properties.nonceValidityMs()),
                Duration.ofMillis(properties.nonceOverlapMs()), random);
    }

    @Bean
    BankingRequestAdmissionUseCase bankingRequestAdmissionUseCase(BankingSessionAdmissionStore store,
                                            SessionProofVerifier proofs,
                                            CustomerContextSigner contexts, Clock clock) {
        return new BankingRequestAdmissionService(store, proofs, contexts, clock);
    }

    @Bean
    PasswordLoginUseCase passwordLoginUseCase(PasswordLoginRouteService routes,
                                                      ActivatePasswordSessionService sessions,
                                                      PasswordAvailabilityPolicy availability) {
        return new PasswordLoginService(routes, sessions, availability);
    }

    private byte[] secret(String encoded) {
        try {
            byte[] decoded = Base64.getDecoder().decode(encoded);
            if (decoded.length < 32) {
                throw new InvalidPasswordRuntimeConfigurationException();
            }
            return decoded;
        } catch (IllegalArgumentException failure) {
            throw new InvalidPasswordRuntimeConfigurationException(failure);
        }
    }
}
