package com.vpbank.dcp.auth.infrastructure.adapter.out.keycloak;

import com.vpbank.dcp.auth.application.port.out.exception.PartnerUnavailableException;
import com.vpbank.dcp.auth.application.port.out.gateway.IdentityProviderPort;
import com.vpbank.dcp.auth.application.port.out.model.NewIdentityUser;
import com.vpbank.dcp.auth.infrastructure.adapter.out.keycloak.constant.KeycloakEndpoints;
import com.vpbank.dcp.auth.infrastructure.adapter.out.keycloak.dto.CreateUserRequest;
import com.vpbank.dcp.auth.infrastructure.adapter.out.keycloak.dto.CredentialRequest;
import com.vpbank.dcp.auth.infrastructure.adapter.out.keycloak.dto.EnableUserRequest;
import com.vpbank.dcp.auth.infrastructure.adapter.out.keycloak.dto.TokenResponse;
import com.vpbank.dcp.auth.infrastructure.adapter.out.keycloak.mapper.KeycloakUserMapper;
import java.net.URI;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

/**
 * Keycloak Admin REST with a service-account token (client credentials), fetched per call. Only
 * the statuses Keycloak documents for success count as success; 409 on create means the
 * username is taken. A timeout or any other status is unavailable, never retried here.
 */
public final class KeycloakAdminAdapter implements IdentityProviderPort {
    private static final String PARTNER = "Keycloak";
    private static final int CREATED = 201;
    private static final int NO_CONTENT = 204;
    private static final int OK = 200;
    private static final int CONFLICT = 409;

    private final RestClient restClient;
    private final String issuer;
    private final String realm;
    private final String clientId;
    private final String clientSecret;

    /** Explicit constructor: it derives the issuer {@code <baseUrl>/realms/<realm>}. */
    public KeycloakAdminAdapter(RestClient restClient, String baseUrl, String realm, String clientId, String clientSecret) {
        this.restClient = Objects.requireNonNull(restClient);
        this.realm = Objects.requireNonNull(realm);
        this.clientId = Objects.requireNonNull(clientId);
        this.clientSecret = Objects.requireNonNull(clientSecret);
        this.issuer = Objects.requireNonNull(baseUrl).replaceAll("/+$", "") + "/realms/" + realm;
    }

    @Override
    public CreateUserResult createDisabledUser(NewIdentityUser newUser) {
        String serviceAccountToken = serviceAccountToken();
        CreateUserRequest createUserRequest = KeycloakUserMapper.toCreateUserRequest(newUser);

        return call(() -> restClient.post()
                .uri(KeycloakEndpoints.ADMIN_USERS, realm)
                .headers(headers -> headers.setBearerAuth(serviceAccountToken))
                .contentType(MediaType.APPLICATION_JSON)
                .body(createUserRequest)
                .exchange((request, response) -> {
                    int status = response.getStatusCode().value();
                    if (status == CONFLICT) {
                        return new CreateUserResult.UserNameTaken();
                    }
                    if (status != CREATED) {
                        throw new PartnerUnavailableException(PARTNER);
                    }

                    URI location = response.getHeaders().getLocation();
                    Optional<String> identitySubject = KeycloakUserMapper.subjectFrom(location);
                    if (identitySubject.isEmpty()) {
                        throw new PartnerUnavailableException(PARTNER);
                    }
                    return new CreateUserResult.Created(issuer, identitySubject.get());
                }));
    }

    @Override
    public void setPassword(String identitySubject, String password) {
        CredentialRequest permanentPassword = KeycloakUserMapper.permanentPassword(password);
        putExpectingNoContent(KeycloakEndpoints.ADMIN_USER_RESET_PASSWORD, identitySubject, permanentPassword);
    }

    @Override
    public void enable(String identitySubject) {
        EnableUserRequest enabledUser = KeycloakUserMapper.enabled();
        putExpectingNoContent(KeycloakEndpoints.ADMIN_USER, identitySubject, enabledUser);
    }

    private void putExpectingNoContent(String path, String identitySubject, Object body) {
        String serviceAccountToken = serviceAccountToken();

        call(() -> restClient.put()
                .uri(path, realm, identitySubject)
                .headers(headers -> headers.setBearerAuth(serviceAccountToken))
                .contentType(MediaType.APPLICATION_JSON)
                .body(body)
                .exchange((request, response) -> {
                    if (response.getStatusCode().value() != NO_CONTENT) {
                        throw new PartnerUnavailableException(PARTNER);
                    }
                    return null;
                }));
    }

    private String serviceAccountToken() {
        MultiValueMap<String, String> clientCredentialsForm = new LinkedMultiValueMap<>();
        clientCredentialsForm.add("grant_type", "client_credentials");
        clientCredentialsForm.add("client_id", clientId);
        clientCredentialsForm.add("client_secret", clientSecret);

        return call(() -> restClient.post()
                .uri(KeycloakEndpoints.TOKEN, realm)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(clientCredentialsForm)
                .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                .exchange((request, response) -> {
                    if (response.getStatusCode().value() != OK) {
                        throw new PartnerUnavailableException(PARTNER);
                    }
                    TokenResponse tokenResponse = response.bodyTo(TokenResponse.class);
                    boolean hasAccessToken = tokenResponse != null
                            && tokenResponse.accessToken() != null
                            && !tokenResponse.accessToken().isBlank();
                    if (!hasAccessToken) {
                        throw new PartnerUnavailableException(PARTNER);
                    }
                    return tokenResponse.accessToken();
                }));
    }

    private static <T> T call(Supplier<T> partnerExchange) {
        try {
            return partnerExchange.get();
        } catch (RestClientException failure) {
            throw new PartnerUnavailableException(PARTNER, failure);
        }
    }
}
