package com.vpbank.dcp.infrastructure.config;

import com.vpbank.dcp.core.application.password.*;
import com.vpbank.dcp.core.domain.device.TrustedDeviceRouting;
import com.vpbank.dcp.core.domain.security.LookupKeyVersion;
import com.vpbank.dcp.core.port.in.password.PasswordLoginUseCase;
import com.vpbank.dcp.core.port.out.customer.CustomerDirectory;
import com.vpbank.dcp.core.port.out.customer.CustomerOwnerRepository;
import com.vpbank.dcp.core.port.out.keycloak.DirectGrantPasswordVerifier;
import com.vpbank.dcp.core.port.out.password.*;
import com.vpbank.dcp.core.port.out.session.*;
import com.vpbank.dcp.infrastructure.adapter.in.web.ExternalUriPolicy;
import com.vpbank.dcp.infrastructure.adapter.in.web.password.PasswordLoginRequestMapper;
import com.vpbank.dcp.infrastructure.adapter.in.web.password.PasswordLoginResponseMapper;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.*;
import com.vpbank.dcp.infrastructure.adapter.out.persistence.session.JpaPasswordSessionAdapter;
import com.vpbank.dcp.infrastructure.adapter.out.persistence.repository.session.PasswordSessionPersistenceRepository;
import com.vpbank.dcp.infrastructure.adapter.out.persistence.repository.session.PasswordDeliveryEscrowCodec;
import com.vpbank.dcp.core.domain.customer.CustomerFreshnessPolicy;
import com.vpbank.dcp.infrastructure.adapter.out.redis.RedisPasswordSessionAuthority;
import com.vpbank.dcp.infrastructure.adapter.out.redis.RedisServerIdentity;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.AuthorityScope;
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
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;

/**
 * Assembles focused use cases; integration activation cannot be enabled in production.
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnWebApplication
@EnableConfigurationProperties({PasswordFlowProperties.class, NativeSessionProperties.class})
public class PasswordFlowConfiguration {

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
                                                 CustomerOwnerRepository owners,
                                                 PasswordFlowProperties properties) {
        return new ConfirmPasswordLoginOwnerService(snapshots, owners,
                properties.customerPolicyVersion());
    }

    @Bean
    ReservePasswordLoginService reservePasswordLogin(PasswordDeviceKeyRepository keys,
                                               PasswordProofVerifier proofs,
                                               PasswordProofReplay replay,
                                               PasswordCommandHasher commands,
                                               PasswordOperationRepository operations) {
        return new ReservePasswordLoginService(keys, proofs, replay, commands, operations);
    }

    @Bean
    VerifyPasswordLoginIdentityService verifyPasswordLoginIdentity(ReservePasswordLoginService admission,
                                                       PasswordOperationRepository operations,
                                                       DirectGrantPasswordVerifier keycloak,
                                                       ConfirmPasswordLoginOwnerService customers,
                                                       Clock clock) {
        return new VerifyPasswordLoginIdentityService(admission, operations, keycloak, customers, clock);
    }

    @Bean
    PasswordLoginRouteService passwordRoutes(VerifyPasswordLoginIdentityService credentials,
                                             PasswordDeviceRouteRepository deviceRoutes,
                                             PasswordOperationRepository operations) {
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
    PasswordSessionPersistenceRepository passwordSessionPersistenceRepository(EntityManager sql) {
        return new PasswordSessionPersistenceRepository(sql);
    }

    @Bean
    PasswordDeliveryEscrowCodec passwordDeliveryEscrowCodec(JsonMapper json) {
        return new PasswordDeliveryEscrowCodec(json);
    }

    @Bean
    CustomerFreshnessPolicy customerFreshnessPolicy(PasswordFlowProperties properties) {
        return new CustomerFreshnessPolicy(Duration.ofMillis(properties.customerStatusMaxAgeMs()));
    }

    @Bean
    PasswordSessionRepository passwordSessionRepository(PasswordSessionPersistenceRepository repository,
            TransactionTemplate transactions, Clock clock, CustomerFreshnessPolicy freshness,
            PasswordDeliveryEscrowCodec escrow) {
        return new JpaPasswordSessionAdapter(repository, transactions, clock, freshness, escrow);
    }

    @Bean
    PasswordSessionAuthority passwordSessionAuthority(StringRedisTemplate redis,
                                                      RedisServerIdentity identity,
                                                      AuthorityScope scope,
                                                      NativeSessionProperties properties,
                                                      Clock clock) {
        return new RedisPasswordSessionAuthority(redis, identity, scope,
                Duration.ofMillis(properties.nonceValidityMs()), clock);
    }

    @Bean
    ActivatePasswordSessionService activatePasswordSession(PasswordSessionRepository store,
                                            PasswordSessionCryptography cryptography,
                                            PasswordSessionAuthority authority, Clock clock) {
        return new ActivatePasswordSessionService(store, cryptography, authority, clock);
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
