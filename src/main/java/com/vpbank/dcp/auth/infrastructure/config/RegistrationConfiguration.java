package com.vpbank.dcp.auth.infrastructure.config;

import com.vpbank.dcp.auth.application.port.in.RegisterCustomerUseCase;
import com.vpbank.dcp.auth.application.port.out.gateway.CustomerDirectoryPort;
import com.vpbank.dcp.auth.application.port.out.gateway.IdentityProviderPort;
import com.vpbank.dcp.auth.application.port.out.gateway.SmsSenderPort;
import com.vpbank.dcp.auth.application.port.out.repository.RegistrationRepository;
import com.vpbank.dcp.auth.application.service.InitialPasswordGenerator;
import com.vpbank.dcp.auth.application.service.RegisterCustomerService;
import com.vpbank.dcp.auth.application.service.RequestDigester;
import com.vpbank.dcp.auth.domain.model.RegistrationId;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ErrorMessages;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.mapper.RegistrationRestMapper;
import com.vpbank.dcp.auth.infrastructure.adapter.out.customer.CustomerHttpAdapter;
import com.vpbank.dcp.auth.infrastructure.adapter.out.keycloak.KeycloakAdminAdapter;
import com.vpbank.dcp.auth.infrastructure.adapter.out.notification.NotificationHttpAdapter;
import java.net.http.HttpClient;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

/**
 * Registration, off by default. The whole object graph of the capability is here: three partner
 * adapters (one bean each, so a test can replace them), the service behind its use case, and the
 * web mapper. Every setting is validated at startup; a bad one stops the application with the
 * setting's name, never its value.
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(prefix = "auth.registration", name = "enabled", havingValue = "true")
@EnableConfigurationProperties(RegistrationProperties.class)
public class RegistrationConfiguration {

    @Bean
    RegistrationRestMapper registrationRestMapper(ErrorMessages errorMessages) {
        return new RegistrationRestMapper(errorMessages);
    }

    @Bean
    RegisterCustomerUseCase registerCustomerUseCase(RegistrationRepository registrationRepository,
                                                    CustomerDirectoryPort customerDirectoryPort,
                                                    IdentityProviderPort identityProviderPort,
                                                    SmsSenderPort smsSenderPort,
                                                    RegistrationProperties properties,
                                                    Clock clock) {
        RequestDigester requestDigester = new RequestDigester(digestKey(properties.requestDigestKeyBase64()));
        InitialPasswordGenerator initialPasswordGenerator =
                new InitialPasswordGenerator(new SecureRandom(), properties.initialPasswordLength());

        return new RegisterCustomerService(
                registrationRepository,
                customerDirectoryPort,
                identityProviderPort,
                smsSenderPort,
                requestDigester,
                initialPasswordGenerator,
                clock,
                properties.requestLifetime(),
                RegistrationId::random);
    }

    @Bean
    CustomerDirectoryPort customerDirectoryPort(RegistrationProperties properties) {
        RegistrationProperties.Customer customer = properties.customer();
        RestClient customerRestClient = restClient(customer.origin(), customer.timeout());
        return new CustomerHttpAdapter(
                customerRestClient,
                customer.profilePath(),
                blankToNull(customer.serviceToken()));
    }

    @Bean
    IdentityProviderPort identityProviderPort(RegistrationProperties properties) {
        RegistrationProperties.Keycloak keycloak = properties.keycloak();
        RestClient keycloakRestClient = restClient(keycloak.baseUrl(), keycloak.timeout());
        return new KeycloakAdminAdapter(
                keycloakRestClient,
                keycloak.baseUrl(),
                keycloak.realm(),
                keycloak.adminClientId(),
                keycloak.adminClientSecret());
    }

    @Bean
    SmsSenderPort smsSenderPort(RegistrationProperties properties) {
        RegistrationProperties.Notification notification = properties.notification();
        RestClient notificationRestClient = restClient(notification.origin(), notification.timeout());
        return new NotificationHttpAdapter(
                notificationRestClient,
                notification.smsPath(),
                notification.serviceToken());
    }

    /** One timeout for connect and read; no retries, no redirects. */
    static RestClient restClient(String baseUrl, Duration timeout) {
        HttpClient httpClient = HttpClient.newBuilder()
                .connectTimeout(timeout)
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
        JdkClientHttpRequestFactory requestFactory = new JdkClientHttpRequestFactory(httpClient);
        requestFactory.setReadTimeout(timeout);
        return RestClient.builder()
                .baseUrl(baseUrl)
                .requestFactory(requestFactory)
                .build();
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
            throw new IllegalStateException("auth.registration.request-digest-key-base64 is not Base64", invalid);
        }
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }
}
