package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import java.util.List;
import lombok.NonNull;

/**
 * The JWK Set the BFF fetches to verify service tokens (slice 12): the public halves of the signing keys, as
 * RFC 7517 JSON, prepared once at startup by configuration. Publishing key material is not a business
 * operation, so the JWKS controller takes this instead of a use case.
 */
public record ServiceTokenPublicKeys(@NonNull String json) {
    /** Only the public members of each key are rendered, whatever the keys given. */
    public static ServiceTokenPublicKeys of(List<JWK> keys) {
        List<JWK> publicKeys = keys.stream().map(JWK::toPublicJWK).toList();
        return new ServiceTokenPublicKeys(new JWKSet(publicKeys).toString(true));
    }
}
