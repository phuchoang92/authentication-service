package com.vpbank.dcp.auth.infrastructure.adapter.out.keycloak;

import com.vpbank.dcp.auth.infrastructure.adapter.out.keycloak.dto.TokenResponse;
import com.vpbank.dcp.auth.infrastructure.adapter.out.keycloak.mapper.KeycloakUserMapper;
import com.vpbank.dcp.auth.application.port.out.gateway.IdentityProviderPort;
import com.vpbank.dcp.auth.application.port.out.model.NewIdentityUser;
import com.vpbank.dcp.auth.application.port.out.exception.PartnerUnavailableException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import java.util.Objects;
import java.util.function.Supplier;

/**
 * Keycloak Admin REST with a service-account token (client credentials), fetched per call. Only
 * the statuses Keycloak documents for success count as success; 409 on create means the
 * username is taken. A timeout or any other status is unavailable, never retried here.
 */
public final class KeycloakAdminAdapter implements IdentityProviderPort {
    private static final String PARTNER = "Keycloak";

    private final RestClient client;
    private final String issuer;
    private final String realm;
    private final String clientId;
    private final String clientSecret;

    /** Explicit constructor: it derives the issuer {@code <baseUrl>/realms/<realm>}. */
    public KeycloakAdminAdapter(RestClient client, String baseUrl, String realm, String clientId, String clientSecret) {
        this.client = Objects.requireNonNull(client);
        this.realm = Objects.requireNonNull(realm);
        this.clientId = Objects.requireNonNull(clientId);
        this.clientSecret = Objects.requireNonNull(clientSecret);
        this.issuer = Objects.requireNonNull(baseUrl).replaceAll("/+$", "") + "/realms/" + realm;
    }

    @Override
    public CreateUserResult createDisabledUser(NewIdentityUser newUser) {
        String token = token();
        return call(() -> client.post().uri("/admin/realms/{realm}/users", realm)
                .headers(headers -> headers.setBearerAuth(token))
                .contentType(MediaType.APPLICATION_JSON)
                .body(KeycloakUserMapper.toCreateUserRequest(newUser))
                .exchange((request, response) -> {
                    int status = response.getStatusCode().value();
                    if (status == 409) {
                        return new CreateUserResult.UserNameTaken();
                    }
                    if (status != 201) {
                        throw new PartnerUnavailableException(PARTNER);
                    }
                    return KeycloakUserMapper.subjectFrom(response.getHeaders().getLocation())
                            .<CreateUserResult>map(subject -> new CreateUserResult.Created(issuer, subject))
                            .orElseThrow(() -> new PartnerUnavailableException(PARTNER));
                }));
    }

    @Override
    public void setPassword(String identitySubject, String password) {
        expectNoContent("/admin/realms/{realm}/users/{id}/reset-password", identitySubject,
                KeycloakUserMapper.permanentPassword(password));
    }

    @Override
    public void enable(String identitySubject) {
        expectNoContent("/admin/realms/{realm}/users/{id}", identitySubject, KeycloakUserMapper.enabled());
    }

    private void expectNoContent(String path, String identitySubject, Object body) {
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
                    if (body == null || body.accessToken() == null || body.accessToken().isBlank()) {
                        throw new PartnerUnavailableException(PARTNER);
                    }
                    return body.accessToken();
                }));
    }

    private static <T> T call(Supplier<T> exchange) {
        try {
            return exchange.get();
        } catch (RestClientException failure) {
            throw new PartnerUnavailableException(PARTNER, failure);
        }
    }
}
