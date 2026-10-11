package com.vpbank.dcp.infrastructure.adapter.out.keycloak;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.net.URI;
import java.time.Instant;
import java.util.Date;
import java.util.Objects;
import java.util.UUID;

/** Fresh RFC 7523 client authentication for each private Keycloak mutation. */
public final class PrivateKeyJwtFactory {

    private static final String CLIENT_ID = "authentication-service";
    private final URI tokenEndpoint;
    private final ECKey signingKey;

    public PrivateKeyJwtFactory(URI tokenEndpoint, ECKey signingKey) {
        this.tokenEndpoint = Objects.requireNonNull(tokenEndpoint, "tokenEndpoint");
        this.signingKey = Objects.requireNonNull(signingKey, "signingKey");
        if (!"https".equals(tokenEndpoint.getScheme()) || tokenEndpoint.getHost() == null
                || tokenEndpoint.getUserInfo() != null || tokenEndpoint.getRawQuery() != null
                || tokenEndpoint.getRawFragment() != null || !tokenEndpoint.getPath().endsWith(
                        "/protocol/openid-connect/token")
                || !signingKey.isPrivate() || !Curve.P_256.equals(signingKey.getCurve())
                || signingKey.getKeyID() == null || signingKey.getKeyID().isBlank()) {
            throw new InvalidKeycloakClientConfigurationException();
        }
    }

    public String issue(Instant now) {
        Objects.requireNonNull(now, "now");
        var claims = new JWTClaimsSet.Builder()
                .issuer(CLIENT_ID)
                .subject(CLIENT_ID)
                .audience(tokenEndpoint.toString())
                .jwtID(UUID.randomUUID().toString())
                .issueTime(Date.from(now))
                .notBeforeTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(30)))
                .build();
        var jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(JOSEObjectType.JWT)
                .keyID(signingKey.getKeyID())
                .build(), claims);
        try {
            jwt.sign(new ECDSASigner(signingKey));
            return jwt.serialize();
        } catch (JOSEException failure) {
            throw new InvalidKeycloakClientConfigurationException(failure);
        }
    }
}
