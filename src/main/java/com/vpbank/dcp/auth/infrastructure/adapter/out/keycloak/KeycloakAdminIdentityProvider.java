package com.vpbank.dcp.auth.infrastructure.adapter.out.keycloak;

import com.vpbank.dcp.auth.core.customer.IdentityProvider;
import com.vpbank.dcp.auth.core.customer.PartnerUnavailableException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Supplier;

/**
 * Keycloak Admin REST with a service-account token (client credentials), fetched per call. Only
 * the statuses Keycloak documents for success count as success; 409 on create means the
 * username is taken. A timeout or any other status is unavailable, never retried here.
 */
public final class KeycloakAdminIdentityProvider implements IdentityProvider {
    private static final String PARTNER = "Keycloak";

    private final RestClient client;
    private final String issuer;
    private final String realm;
    private final String clientId;
    private final String clientSecret;

    /** {@code client} has the Keycloak base URL; the issuer is {@code <baseUrl>/realms/<realm>}. */
    public KeycloakAdminIdentityProvider(RestClient client, String baseUrl, String realm,
                                         String clientId, String clientSecret) {
        this.client = Objects.requireNonNull(client);
        this.realm = Objects.requireNonNull(realm);
        this.clientId = Objects.requireNonNull(clientId);
        this.clientSecret = Objects.requireNonNull(clientSecret);
        this.issuer = Objects.requireNonNull(baseUrl).replaceAll("/+$", "") + "/realms/" + realm;
    }

    @Override
    public CreateUserResult createDisabledUser(String userName, String firstName, String lastName,
                                               String email, boolean emailVerified) {
        Map<String, Object> user = new LinkedHashMap<>();
        user.put("username", userName);
        user.put("firstName", firstName);
        user.put("lastName", lastName);
        if (email != null) {
            user.put("email", email);
            user.put("emailVerified", emailVerified);
        }
        user.put("enabled", false);
        user.put("requiredActions", List.of());
        String token = token();
        return call(() -> client.post().uri("/admin/realms/{realm}/users", realm)
                .headers(headers -> headers.setBearerAuth(token))
                .contentType(MediaType.APPLICATION_JSON).body(user)
                .exchange((request, response) -> {
                    int status = response.getStatusCode().value();
                    if (status == 409) {
                        return new CreateUserResult.UserNameTaken();
                    }
                    URI location = response.getHeaders().getLocation();
                    if (status != 201 || location == null) {
                        throw new PartnerUnavailableException(PARTNER);
                    }
                    String path = location.getPath();
                    String subject = path.substring(path.lastIndexOf('/') + 1);
                    if (subject.isBlank()) {
                        throw new PartnerUnavailableException(PARTNER);
                    }
                    return new CreateUserResult.Created(issuer, subject);
                }));
    }

    @Override
    public void setPassword(String identitySubject, String password) {
        Map<String, Object> credential = Map.of("type", "password", "value", password, "temporary", false);
        expectNoContent("/admin/realms/{realm}/users/{id}/reset-password", identitySubject, credential);
    }

    @Override
    public void enable(String identitySubject) {
        expectNoContent("/admin/realms/{realm}/users/{id}", identitySubject, Map.of("enabled", true));
    }

    private void expectNoContent(String path, String identitySubject, Map<String, Object> body) {
        String token = token();
        call(() -> client.put().uri(path, realm, identitySubject)
                .headers(headers -> headers.setBearerAuth(token))
                .contentType(MediaType.APPLICATION_JSON).body(body)
                .exchange((request, response) -> {
                    if (response.getStatusCode().value() != 204) {
                        throw new PartnerUnavailableException(PARTNER);
                    }
                    return null;
                }));
    }

    private String token() {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "client_credentials");
        form.add("client_id", clientId);
        form.add("client_secret", clientSecret);
        return call(() -> client.post().uri("/realms/{realm}/protocol/openid-connect/token", realm)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED).body(form)
                .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                .exchange((request, response) -> {
                    if (response.getStatusCode().value() != 200) {
                        throw new PartnerUnavailableException(PARTNER);
                    }
                    TokenResponse body = response.bodyTo(TokenResponse.class);
                    if (body == null || body.access_token() == null || body.access_token().isBlank()) {
                        throw new PartnerUnavailableException(PARTNER);
                    }
                    return body.access_token();
                }));
    }

    private static <T> T call(Supplier<T> exchange) {
        try {
            return exchange.get();
        } catch (RestClientException failure) {
            throw new PartnerUnavailableException(PARTNER, failure);
        }
    }

    /** The token endpoint's JSON uses snake_case. */
    record TokenResponse(String access_token) { }
}
