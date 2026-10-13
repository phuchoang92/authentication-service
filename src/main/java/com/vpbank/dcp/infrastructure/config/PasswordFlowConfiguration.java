package com.vpbank.dcp.infrastructure.config;

import com.vpbank.dcp.core.application.password.CheckCustomerLoginEligibilityService;
import com.vpbank.dcp.core.application.password.CheckPasswordLoginEligibilityService;
import com.vpbank.dcp.core.application.password.ConfirmPasswordLoginOwnerService;
import com.vpbank.dcp.core.application.password.PasswordAvailabilityPolicy;
import com.vpbank.dcp.core.application.password.PasswordLoginService;
import com.vpbank.dcp.core.application.password.ReservePasswordLoginService;
import com.vpbank.dcp.core.application.password.ResolveTrustedDeviceRouteService;
import com.vpbank.dcp.core.application.password.VerifyPasswordLoginIdentityService;
import com.vpbank.dcp.core.domain.device.TrustedDeviceRouting;
import com.vpbank.dcp.core.port.in.password.PasswordLoginUseCase;
import com.vpbank.dcp.core.port.in.session.ActivateSessionUseCase;
import com.vpbank.dcp.core.port.out.customer.CustomerDirectory;
import com.vpbank.dcp.core.port.out.customer.CustomerOwnerRepository;
import com.vpbank.dcp.core.port.out.keycloak.DirectGrantPasswordVerifier;
import com.vpbank.dcp.core.port.out.password.PasswordCommandHasher;
import com.vpbank.dcp.core.port.out.password.PasswordDeviceKeyRepository;
import com.vpbank.dcp.core.port.out.password.PasswordDeviceRouteRepository;
import com.vpbank.dcp.core.port.out.password.PasswordOperationRepository;
import com.vpbank.dcp.core.port.out.password.PasswordProofReplay;
import com.vpbank.dcp.core.port.out.password.PasswordProofVerifier;
import com.vpbank.dcp.core.port.out.session.SessionRepository;
import com.vpbank.dcp.infrastructure.adapter.in.web.password.PasswordLoginRequestMapper;
import com.vpbank.dcp.infrastructure.adapter.in.web.password.PasswordLoginResponseMapper;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.LengthPrefixedSigningInputEncoder;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.PasswordCommandHmac;
import com.vpbank.dcp.infrastructure.persistence.adapter.JpaPasswordSessionAdapter;
import com.vpbank.dcp.infrastructure.persistence.repository.PasswordSessionPersistenceRepository;
import com.vpbank.dcp.infrastructure.persistence.repository.SessionPersistenceRepository;
import com.vpbank.dcp.infrastructure.persistence.codec.SessionDeliveryEscrowCodec;
import com.vpbank.dcp.core.domain.customer.CustomerFreshnessPolicy;
import com.vpbank.dcp.infrastructure.config.properties.NativeSessionProperties;
import com.vpbank.dcp.infrastructure.config.properties.PasswordFlowProperties;
import jakarta.persistence.EntityManager;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.transaction.support.TransactionTemplate;
import tools.jackson.databind.json.JsonMapper;

import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;

/**
 * Assembles focused use cases; integration activation cannot be enabled in production.
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnWebApplication
@EnableConfigurationProperties(PasswordFlowProperties.class)
public class PasswordFlowConfiguration {

    @Bean
    PasswordLoginRequestMapper passwordLoginRequestMapper(PasswordFlowProperties policy,
                                                              JsonMapper json, Clock clock) {
        return new PasswordLoginRequestMapper(policy, json, clock);
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
    CheckPasswordLoginEligibilityService passwordLoginEligibility(VerifyPasswordLoginIdentityService credentials,
                                             PasswordDeviceRouteRepository deviceRoutes,
                                             PasswordOperationRepository operations) {
        return new CheckPasswordLoginEligibilityService(credentials,
                new ResolveTrustedDeviceRouteService(deviceRoutes, new TrustedDeviceRouting()), operations);
    }

    @Bean
    PasswordSessionPersistenceRepository passwordSessionPersistenceRepository(EntityManager sql) {
        return new PasswordSessionPersistenceRepository(sql);
    }

    @Bean
    CustomerFreshnessPolicy customerFreshnessPolicy(PasswordFlowProperties properties) {
        return new CustomerFreshnessPolicy(Duration.ofMillis(properties.customerStatusMaxAgeMs()));
    }

    @Bean
    SessionRepository passwordSessionRepository(PasswordSessionPersistenceRepository repository,
            SessionPersistenceRepository sessions, TransactionTemplate transactions, Clock clock,
            CustomerFreshnessPolicy freshness,
            SessionDeliveryEscrowCodec escrow) {
        return new JpaPasswordSessionAdapter(repository, sessions, transactions, clock, freshness, escrow);
    }

    @Bean
    PasswordLoginUseCase passwordLoginUseCase(CheckPasswordLoginEligibilityService eligibility,
                                                      ActivateSessionUseCase sessions,
                                                      PasswordAvailabilityPolicy availability) {
        return new PasswordLoginService(eligibility, sessions, availability);
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
