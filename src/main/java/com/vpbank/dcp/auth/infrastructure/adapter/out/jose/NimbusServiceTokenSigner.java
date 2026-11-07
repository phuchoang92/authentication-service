package com.vpbank.dcp.auth.infrastructure.adapter.out.jose;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.vpbank.dcp.auth.application.port.out.gateway.ServiceTokenSigner;
import com.vpbank.dcp.auth.domain.model.ServiceTokenClaims;

import java.util.Date;
import lombok.NonNull;

/**
 * The service token as compact JWS (slice 12): {@code alg=ES256}, {@code typ=service-token+jwt}, {@code kid} of
 * the signing key, no key material in the header. Claims are exactly {@code iss, sub, aud, scope, iat, exp, jti}
 * plus {@code businessReference} when the claims carry one; the BFF rejects any other set. The signing key is
 * the service-token key and nothing else (DD 01: keys are separated by purpose).
 */
public final class NimbusServiceTokenSigner implements ServiceTokenSigner {
    public static final JOSEObjectType TOKEN_TYPE = new JOSEObjectType("service-token+jwt");
    public static final String SCOPE_CLAIM = "scope";
    public static final String BUSINESS_REFERENCE_CLAIM = "businessReference";

    private final ECKey signingKey;

    /**
     * {@code signingKey} is the private P-256 key; it must carry the key ID the header names.
     */
    public NimbusServiceTokenSigner(@NonNull ECKey signingKey) {
        this.signingKey = signingKey;
        if (!signingKey.isPrivate() || !Curve.P_256.equals(signingKey.getCurve()) || signingKey.getKeyID() == null) {
            throw new IllegalArgumentException("The service token signing key must be a private P-256 key with a key ID");
        }
    }

    @Override
    public String sign(ServiceTokenClaims claims) {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(TOKEN_TYPE)
                .keyID(signingKey.getKeyID())
                .build();
        JWTClaimsSet.Builder claimSet = new JWTClaimsSet.Builder()
                .issuer(claims.issuer())
                .subject(claims.issuedTo().value())
                .audience(claims.audience())
                .claim(SCOPE_CLAIM, claims.scope().code())
                .issueTime(Date.from(claims.issuedAt()))
                .expirationTime(Date.from(claims.expiresAt()))
                .jwtID(claims.tokenId().toString());
        if (claims.businessReference() != null) {
            claimSet.claim(BUSINESS_REFERENCE_CLAIM, claims.businessReference().value());
        }
        try {
            SignedJWT token = new SignedJWT(header, claimSet.build());
            token.sign(new ECDSASigner(signingKey));
            return token.serialize();
        } catch (JOSEException failure) {
            throw new IllegalStateException("Service token could not be signed", failure);
        }
    }
}
