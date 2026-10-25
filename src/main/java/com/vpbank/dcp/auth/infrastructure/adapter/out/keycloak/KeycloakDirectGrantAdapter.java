package com.vpbank.dcp.auth.infrastructure.adapter.out.keycloak;

import com.vpbank.dcp.auth.application.port.out.exception.PartnerUnavailableException;
import com.vpbank.dcp.auth.application.port.out.gateway.CredentialVerifierPort;
import com.vpbank.dcp.auth.domain.model.Password;
import com.vpbank.dcp.auth.domain.model.UserName;
import com.vpbank.dcp.auth.infrastructure.adapter.out.keycloak.constant.KeycloakEndpoints;
import com.vpbank.dcp.auth.infrastructure.adapter.out.keycloak.dto.DirectGrantResponse;
import com.vpbank.dcp.auth.infrastructure.adapter.out.keycloak.mapper.KeycloakCredentialMapper;
import java.util.Optional;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

/**
 * Password check through Keycloak Direct Grant (client_id + client_secret). 200 with a valid
 * KC-signed ID token → verified issuer/subject; 400/401 {@code invalid_grant} → rejected;
 * anything else, a timeout or an unverifiable token → unavailable, never retried here.
 */
@RequiredArgsConstructor
public final class KeycloakDirectGrantAdapter implements CredentialVerifierPort {
    private static final String PARTNER = "Keycloak";
    private static final String INVALID_GRANT = "invalid_grant";
    private static final int OK = 200;
    private static final int BAD_REQUEST = 400;
    private static final int UNAUTHORIZED = 401;

    @NonNull private final RestClient restClient;
    @NonNull private final String realm;
    @NonNull private final String issuer;
    @NonNull private final String clientId;
    @NonNull private final String clientSecret;
    @NonNull private final KeycloakIdTokenVerifier keycloakIdTokenVerifier;

    @Override
    public VerificationResult verify(UserName userName, Password password) {
        MultiValueMap<String, String> passwordGrantForm =
                KeycloakCredentialMapper.passwordGrant(clientId, clientSecret, userName, password);
        try {
            return restClient.post()
                    .uri(KeycloakEndpoints.TOKEN, realm)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .accept(MediaType.APPLICATION_JSON)
                    .body(passwordGrantForm)
                    .exchange((request, response) -> {
                        int status = response.getStatusCode().value();
                        DirectGrantResponse directGrantResponse = response.bodyTo(DirectGrantResponse.class);

                        boolean rejectedStatus = status == BAD_REQUEST || status == UNAUTHORIZED;
                        boolean invalidGrant = directGrantResponse != null
                                && INVALID_GRANT.equals(directGrantResponse.error());
                        if (rejectedStatus && invalidGrant) {
                            return new VerificationResult.Rejected();
                        }

                        boolean hasIdToken = directGrantResponse != null && directGrantResponse.idToken() != null;
                        if (status != OK || !hasIdToken) {
                            throw new PartnerUnavailableException(PARTNER);
                        }

                        Optional<String> verifiedSubject =
                                keycloakIdTokenVerifier.verifiedSubject(directGrantResponse.idToken());
                        if (verifiedSubject.isEmpty()) {
                            throw new PartnerUnavailableException(PARTNER);
                        }
                        return new VerificationResult.Verified(issuer, verifiedSubject.get());
                    });
        } catch (RestClientException failure) {
            throw new PartnerUnavailableException(PARTNER, failure);
        }
    }
}
