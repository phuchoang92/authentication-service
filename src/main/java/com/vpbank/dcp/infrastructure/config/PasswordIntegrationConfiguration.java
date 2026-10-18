package com.vpbank.dcp.infrastructure.config;

import com.vpbank.dcp.core.application.password.CustomerIdentities;
import com.vpbank.dcp.core.application.password.LoginDevices;
import com.vpbank.dcp.core.application.password.PasswordAvailabilityPolicy;
import com.vpbank.dcp.core.application.password.PasswordLoginService;
import com.vpbank.dcp.core.application.password.PasswordProofs;
import com.vpbank.dcp.core.application.password.StartTotpLoginService;
import com.vpbank.dcp.core.application.session.IssueLoginSessionService;
import com.vpbank.dcp.core.domain.device.DeviceTrustPolicy;
import com.vpbank.dcp.core.port.in.customer.CheckCustomerLoginEligibilityUseCase;
import com.vpbank.dcp.core.port.in.password.PasswordLoginUseCase;
import com.vpbank.dcp.core.port.in.session.IssueLoginSessionUseCase;
import com.vpbank.dcp.core.port.out.customer.CustomerOwnerRepository;
import com.vpbank.dcp.core.port.out.device.LoginDeviceRepository;
import com.vpbank.dcp.core.port.out.credential.PasswordVerifier;
import com.vpbank.dcp.core.port.out.password.PasswordProofReplay;
import com.vpbank.dcp.core.port.out.password.PasswordProofVerifier;
import com.vpbank.dcp.core.port.out.session.LoginSessionSecurityStore;
import com.vpbank.dcp.core.port.out.session.SessionAuthority;
import com.vpbank.dcp.core.port.out.session.SessionCryptography;
import com.vpbank.dcp.infrastructure.config.properties.CustomerLoginEligibilityProperties;
import com.vpbank.dcp.infrastructure.config.properties.PasswordFlowProperties;
import java.time.Duration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

/** Wires only the integration-only login slice, keeping technical configuration declarative. */
@Configuration(proxyBeanMethods = false)
@ConditionalOnWebApplication
@Profile("integration")
@ConditionalOnProperty(prefix = "auth.native-session", name = "integration-activation-enabled",
        havingValue = "true")
public class PasswordIntegrationConfiguration {

    @Bean
    PasswordProofs passwordProofs(LoginDeviceRepository devices, PasswordProofVerifier proofs,
                                  PasswordProofReplay replay) {
        return new PasswordProofs(devices, proofs, replay);
    }

    @Bean
    CustomerIdentities customerIdentities(PasswordVerifier passwords,
                                          CheckCustomerLoginEligibilityUseCase customers,
                                          CustomerOwnerRepository owners,
                                          PasswordFlowProperties policy) {
        return new CustomerIdentities(passwords, customers, owners, policy.customerPolicyVersion());
    }

    @Bean
    LoginDevices loginDevices(LoginDeviceRepository devices) {
        return new LoginDevices(devices, new DeviceTrustPolicy());
    }

    @Bean
    IssueLoginSessionUseCase issueLoginSessionUseCase(LoginSessionSecurityStore security,
                                                     SessionCryptography cryptography,
                                                     SessionAuthority authority,
                                                     CustomerLoginEligibilityProperties policy) {
        return new IssueLoginSessionService(security, cryptography, authority,
                Duration.ofMillis(policy.statusMaxAgeMs()));
    }

    @Bean
    PasswordLoginUseCase activePasswordLoginUseCase(PasswordProofs proofs,
                                                    CustomerIdentities identities,
                                                    LoginDevices devices,
                                                    IssueLoginSessionUseCase sessions,
                                                    StartTotpLoginService totp) {
        return new PasswordLoginService(proofs, identities, devices, sessions, totp,
                new PasswordAvailabilityPolicy(true));
    }
}
