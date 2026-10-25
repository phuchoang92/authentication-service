package com.vpbank.dcp.infrastructure.config;

import com.vpbank.dcp.core.password.CustomerIdentities;
import com.vpbank.dcp.core.password.LoginDevices;
import com.vpbank.dcp.core.password.PasswordLoginService;
import com.vpbank.dcp.core.password.PasswordProofs;
import com.vpbank.dcp.core.session.IssueLoginSessionService;
import com.vpbank.dcp.core.session.TrustedDeviceSessions;
import com.vpbank.dcp.core.device.DeviceTrustPolicy;
import com.vpbank.dcp.core.customer.CheckCustomerLoginEligibilityService;
import com.vpbank.dcp.core.customer.CustomerOwnerRepository;
import com.vpbank.dcp.core.device.LoginDeviceRepository;
import com.vpbank.dcp.core.password.PasswordVerifier;
import com.vpbank.dcp.core.password.PasswordProofReplay;
import com.vpbank.dcp.core.password.PasswordProofVerifier;
import com.vpbank.dcp.core.session.LoginSessionSecurityStore;
import com.vpbank.dcp.core.session.SessionAuthority;
import com.vpbank.dcp.core.session.SessionCryptography;
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
                                          CheckCustomerLoginEligibilityService customers,
                                          CustomerOwnerRepository owners,
                                          PasswordFlowProperties policy) {
        return new CustomerIdentities(passwords, customers, owners, policy.customerPolicyVersion());
    }

    @Bean
    LoginDevices loginDevices(LoginDeviceRepository devices) {
        return new LoginDevices(devices, new DeviceTrustPolicy());
    }

    @Bean
    IssueLoginSessionService issueLoginSessionService(LoginSessionSecurityStore security,
                                                     SessionCryptography cryptography,
                                                     SessionAuthority authority,
                                                     CustomerLoginEligibilityProperties policy) {
        return new IssueLoginSessionService(security, cryptography, authority,
                Duration.ofMillis(policy.statusMaxAgeMs()));
    }

    @Bean
    PasswordLoginService passwordLoginService(PasswordProofs proofs,
                                                    CustomerIdentities identities,
                                                    LoginDevices devices,
                                                    IssueLoginSessionService sessions,
                                                    TrustedDeviceSessions trustedDevices) {
        return new PasswordLoginService(proofs, identities, devices, sessions, trustedDevices);
    }
}
