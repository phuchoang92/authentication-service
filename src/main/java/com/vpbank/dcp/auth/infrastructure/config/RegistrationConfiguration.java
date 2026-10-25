package com.vpbank.dcp.auth.infrastructure.config;

import com.vpbank.dcp.auth.core.customer.CustomerDirectory;
import com.vpbank.dcp.auth.core.customer.CustomerRegistrationService;
import com.vpbank.dcp.auth.core.customer.IdentityProvider;
import com.vpbank.dcp.auth.core.customer.InitialPasswordGenerator;
import com.vpbank.dcp.auth.core.customer.RegistrationStore;
import com.vpbank.dcp.auth.core.customer.RequestDigester;
import com.vpbank.dcp.auth.core.customer.SmsSender;
import com.vpbank.dcp.auth.infrastructure.adapter.out.customer.HttpCustomerDirectory;
import com.vpbank.dcp.auth.infrastructure.adapter.out.keycloak.KeycloakAdminIdentityProvider;
import com.vpbank.dcp.auth.infrastructure.adapter.out.notification.HttpSmsSender;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

import java.net.http.HttpClient;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.UUID;

/**
 * Registration, off by default. When on, every partner setting is validated at startup and a
 * bad one stops the application with the setting's name (never its value).
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(prefix = "auth.registration", name = "enabled", havingValue = "true")
@EnableConfigurationProperties(RegistrationProperties.class)
public class RegistrationConfiguration {

    @Bean
    CustomerRegistrationService customerRegistrationService(RegistrationStore store,
                                                            RegistrationProperties properties, Clock clock) {
        return new CustomerRegistrationService(store, customerDirectory(properties.customer()),
                identityProvider(properties.keycloak()), smsSender(properties.notification()),
                new RequestDigester(digestKey(properties.requestDigestKeyBase64())),
                new InitialPasswordGenerator(new SecureRandom(), properties.initialPasswordLength()),
                clock, properties.requestLifetime(), UUID::randomUUID);
    }

    private static CustomerDirectory customerDirectory(RegistrationProperties.Customer customer) {
        return new HttpCustomerDirectory(restClient(customer.origin(), customer.timeout()),
                customer.profilePath(), blankToNull(customer.serviceToken()));
    }

    private static IdentityProvider identityProvider(RegistrationProperties.Keycloak keycloak) {
        return new KeycloakAdminIdentityProvider(restClient(keycloak.baseUrl(), keycloak.timeout()),
                keycloak.baseUrl(), keycloak.realm(), keycloak.adminClientId(), keycloak.adminClientSecret());
    }

    private static SmsSender smsSender(RegistrationProperties.Notification notification) {
        return new HttpSmsSender(restClient(notification.origin(), notification.timeout()),
                notification.smsPath(), notification.serviceToken());
    }

    /** One timeout for connect and read; no retries, no redirects. */
    static RestClient restClient(String baseUrl, Duration timeout) {
        HttpClient http = HttpClient.newBuilder().connectTimeout(timeout)
                .followRedirects(HttpClient.Redirect.NEVER).build();
        JdkClientHttpRequestFactory requests = new JdkClientHttpRequestFactory(http);
        requests.setReadTimeout(timeout);
        return RestClient.builder().baseUrl(baseUrl).requestFactory(requests).build();
    }

    private static byte[] digestKey(String base64) {
        try {
            byte[] key = Base64.getDecoder().decode(base64);
            if (key.length < 32) {
                throw new IllegalStateException(
                        "auth.registration.request-digest-key-base64 must decode to at least 32 bytes");
            }
            return key;
        } catch (IllegalArgumentException invalid) {
            throw new IllegalStateException("auth.registration.request-digest-key-base64 is not Base64",
                    invalid);
        }
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }
}
