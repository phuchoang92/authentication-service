package com.vpbank.dcp.auth.boot;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.vpbank.dcp.auth.adapter.out.persistence.repository.CustomerAuthenticationJpaRepository;
import com.vpbank.dcp.auth.application.port.out.CustomerDirectoryPort;
import com.vpbank.dcp.auth.application.port.out.CustomerProfile;
import com.vpbank.dcp.auth.application.port.out.IdentityProviderPort;
import com.vpbank.dcp.auth.application.port.out.IdentityProviderPort.CreateUserResult;
import com.vpbank.dcp.auth.application.port.out.SmsSenderPort;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import java.util.Base64;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * The whole application boots against real MySQL (Flyway + JPA validation) with registration on,
 * and one request runs web → use case → JPA. The three partner ports are replaced by mocks, so
 * no Customer, Keycloak or Notification service is called.
 */
@Testcontainers
@SpringBootTest(properties = {
        "auth.registration.enabled=true",
        "auth.registration.customer.origin=https://customer.test",
        "auth.registration.keycloak.base-url=https://kc.test",
        "auth.registration.keycloak.realm=test",
        "auth.registration.keycloak.admin-client-id=auth-admin",
        "auth.registration.keycloak.admin-client-secret=secret",
        "auth.registration.notification.origin=https://notify.test",
        "auth.registration.notification.service-token=token"})
@AutoConfigureMockMvc
class ApplicationBootIT {
    @Container
    static final MySQLContainer<?> MYSQL = new MySQLContainer<>("mysql:8.4");
    private static final String BODY = """
            {"customerId":"90359","userName":"alice","firstName":"Alice","lastName":"Nguyen",
             "phoneNumber":"+84901234567"}""";

    @DynamicPropertySource
    static void settings(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", MYSQL::getJdbcUrl);
        registry.add("spring.datasource.username", MYSQL::getUsername);
        registry.add("spring.datasource.password", MYSQL::getPassword);
        registry.add("auth.registration.request-digest-key-base64",
                () -> Base64.getEncoder().encodeToString(new byte[32]));
    }

    @Autowired MockMvc mvc;
    @Autowired CustomerAuthenticationJpaRepository identities;
    @MockitoBean CustomerDirectoryPort customers;
    @MockitoBean IdentityProviderPort keycloak;
    @MockitoBean SmsSenderPort sms;

    @Test
    void registersACustomerEndToEndAndAnswersARetryFromTheDatabase() throws Exception {
        when(customers.profile(new CustomerId("90359"))).thenReturn(Optional.of(CustomerProfile.builder()
                .customerId(new CustomerId("90359")).eligible(true).phone("+84901234567").phoneVerified(true).build()));
        when(keycloak.createDisabledUser(any())).thenReturn(new CreateUserResult.Created("https://kc.test/realms/test", "sub-1"));
        when(sms.sendInitialPassword(any())).thenReturn(true);

        mvc.perform(post("/internal/v1/callback/authentication-creation").header("Accept-Language", "en")
                        .contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isCreated())
                .andExpect(header().exists("X-Correlation-Id"))
                .andExpect(jsonPath("$.data.state").value("READY"));
        mvc.perform(post("/internal/v1/callback/authentication-creation")
                        .contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.userName").value("alice"));
        mvc.perform(post("/internal/v1/callback/authentication-creation")
                        .contentType(MediaType.APPLICATION_JSON).content(BODY.replace("Nguyen", "Tran")))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error.code").value("IDENTITY_CONFLICT"))
                .andExpect(jsonPath("$.error.message").value(org.hamcrest.Matchers.startsWith("Khách hàng")));

        assertThat(identities.findById("90359").orElseThrow().getIdentitySubject()).isEqualTo("sub-1");
    }
}
