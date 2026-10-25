package com.vpbank.dcp.auth.adapter.out.keycloak.mapper;

import com.vpbank.dcp.auth.domain.model.Password;
import com.vpbank.dcp.auth.domain.model.UserName;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/** Port values → Direct Grant form. The password is copied into the form only for the call. */
public final class KeycloakCredentialMapper {
    private KeycloakCredentialMapper() {
    }

    public static MultiValueMap<String, String> passwordGrant(String clientId, String clientSecret,
                                                              UserName userName, Password password) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "password");
        form.add("client_id", clientId);
        form.add("client_secret", clientSecret);
        form.add("scope", "openid");
        form.add("username", userName.value());
        form.add("password", new String(password.value()));
        return form;
    }
}
