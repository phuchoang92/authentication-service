package com.vpbank.dcp.auth.adapter.out.keycloak;

import com.vpbank.dcp.auth.adapter.out.keycloak.dto.DirectGrantResponse;
import com.vpbank.dcp.auth.adapter.out.keycloak.mapper.KeycloakCredentialMapper;
import com.vpbank.dcp.auth.application.port.out.CredentialVerifierPort;
import com.vpbank.dcp.auth.application.port.out.PartnerUnavailableException;
import com.vpbank.dcp.auth.domain.model.Password;
import com.vpbank.dcp.auth.domain.model.UserName;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
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

    @NonNull private final RestClient client;
    @NonNull private final String realm;
    @NonNull private final String issuer;
    @NonNull private final String clientId;
    @NonNull private final String clientSecret;
    @NonNull private final KeycloakIdTokenVerifier idTokens;

    @Override
    public VerificationResult verify(UserName userName, Password password) {
        try {
            return client.post().uri("/realms/{realm}/protocol/openid-connect/token", realm)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED).accept(MediaType.APPLICATION_JSON)
                    .body(KeycloakCredentialMapper.passwordGrant(clientId, clientSecret, userName, password))
                    .exchange((request, response) -> {
                        int status = response.getStatusCode().value();
                        DirectGrantResponse body = response.bodyTo(DirectGrantResponse.class);
                        if ((status == 400 || status == 401) && body != null && "invalid_grant".equals(body.error())) {
                            return new VerificationResult.Rejected();
                        }
                        if (status != 200 || body == null || body.idToken() == null) {
                            throw new PartnerUnavailableException(PARTNER);
                        }
                        return idTokens.verifiedSubject(body.idToken())
                                .<VerificationResult>map(subject -> new VerificationResult.Verified(issuer, subject))
                                .orElseThrow(() -> new PartnerUnavailableException(PARTNER));
                    });
        } catch (RestClientException failure) {
            throw new PartnerUnavailableException(PARTNER, failure);
        }
    }
}
