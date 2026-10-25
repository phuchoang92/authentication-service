package com.vpbank.dcp.auth.infrastructure.adapter.out.keycloak;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.jsonPath;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withCreatedEntity;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withException;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withNoContent;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import com.vpbank.dcp.auth.application.port.out.gateway.IdentityProviderPort.CreateUserResult;
import com.vpbank.dcp.auth.application.port.out.model.NewIdentityUser;
import com.vpbank.dcp.auth.application.port.out.exception.PartnerUnavailableException;
import com.vpbank.dcp.auth.domain.model.Email;
import com.vpbank.dcp.auth.domain.model.UserName;
import java.net.SocketTimeoutException;
import java.net.URI;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

class KeycloakAdminAdapterTest {
    private static final String BASE = "https://kc.test";
    private final RestClient.Builder builder = RestClient.builder().baseUrl(BASE);
    private final MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
    private final KeycloakAdminAdapter keycloak = new KeycloakAdminAdapter(builder.build(),
            BASE + "/", "test", "auth-admin", "secret");

    @Test
    void createsTheUserDisabledWithNoRequiredActions() {
        expectToken();
        server.expect(requestTo(BASE + "/admin/realms/test/users"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header("Authorization", "Bearer admin-token"))
                .andExpect(jsonPath("$.username").value("alice"))
                .andExpect(jsonPath("$.firstName").value("Alice"))
                .andExpect(jsonPath("$.enabled").value(false))
                .andExpect(jsonPath("$.requiredActions").isEmpty())
                .andExpect(jsonPath("$.email").doesNotExist())
                .andRespond(withCreatedEntity(URI.create(BASE + "/admin/realms/test/users/sub-1")));

        assertThat(keycloak.createDisabledUser(alice(null)))
                .isEqualTo(new CreateUserResult.Created(BASE + "/realms/test", "sub-1"));
        server.verify();
    }

    @Test
    void anExistingUserNameIsTaken() {
        expectToken();
        server.expect(requestTo(BASE + "/admin/realms/test/users")).andRespond(withStatus(HttpStatus.CONFLICT));

        assertThat(keycloak.createDisabledUser(alice("a@b.co")))
                .isInstanceOf(CreateUserResult.UserNameTaken.class);
    }

    @Test
    void setsAPermanentPasswordAndEnablesTheUser() {
        expectToken();
        server.expect(requestTo(BASE + "/admin/realms/test/users/sub-1/reset-password"))
                .andExpect(method(HttpMethod.PUT))
                .andExpect(jsonPath("$.type").value("password"))
                .andExpect(jsonPath("$.value").value("Secret123"))
                .andExpect(jsonPath("$.temporary").value(false))
                .andRespond(withNoContent());
        expectToken();
        server.expect(requestTo(BASE + "/admin/realms/test/users/sub-1"))
                .andExpect(method(HttpMethod.PUT))
                .andExpect(content().json("{\"enabled\":true}"))
                .andRespond(withNoContent());

        keycloak.setPassword("sub-1", "Secret123");
        keycloak.enable("sub-1");
        server.verify();
    }

    @Test
    void aFailedTokenAnErrorOrATimeoutIsUnavailable() {
        server.expect(requestTo(BASE + "/realms/test/protocol/openid-connect/token"))
                .andRespond(withStatus(HttpStatus.UNAUTHORIZED));
        assertThatThrownBy(() -> keycloak.enable("sub-1")).isInstanceOf(PartnerUnavailableException.class);

        server.reset();
        expectToken();
        server.expect(requestTo(BASE + "/admin/realms/test/users")).andRespond(withStatus(HttpStatus.BAD_GATEWAY));
        assertThatThrownBy(() -> keycloak.createDisabledUser(alice(null)))
                .isInstanceOf(PartnerUnavailableException.class);

        server.reset();
        expectToken();
        server.expect(requestTo(BASE + "/admin/realms/test/users/sub-1"))
                .andRespond(withException(new SocketTimeoutException("slow")));
        assertThatThrownBy(() -> keycloak.enable("sub-1")).isInstanceOf(PartnerUnavailableException.class);
    }

    private static NewIdentityUser alice(String email) {
        return NewIdentityUser.builder().userName(new UserName("alice")).firstName("Alice").lastName("Nguyen")
                .email(email == null ? null : new Email(email)).emailVerified(email != null).build();
    }

    private void expectToken() {
        server.expect(requestTo(BASE + "/realms/test/protocol/openid-connect/token"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_FORM_URLENCODED))
                .andExpect(content().formDataContains(java.util.Map.of("grant_type", "client_credentials",
                        "client_id", "auth-admin", "client_secret", "secret")))
                .andRespond(withSuccess("{\"access_token\":\"admin-token\",\"expires_in\":60}",
                        MediaType.APPLICATION_JSON));
    }
}
