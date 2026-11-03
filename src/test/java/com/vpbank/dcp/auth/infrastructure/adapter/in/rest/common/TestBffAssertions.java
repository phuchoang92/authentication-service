package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

/** Plays the BFF in tests: one test signing key and well-formed assertions (DD 20 §6a + slice 11 claims). */
public final class TestBffAssertions {
    public static final String ISSUER = "mobile-bff";
    public static final String KEY_ID = "bff-test-1";
    public static final ECKey KEY = generate();

    private TestBffAssertions() {
    }

    /** The public half, as the {@code auth.bff.assertion-public-jwk} setting carries it. */
    public static String publicJwk() {
        return KEY.toPublicJWK().toJSONString();
    }

    public static ECKey publicKey() {
        return KEY.toPublicJWK();
    }

    /** A fresh, current assertion for one session; a new {@code jti} each time. */
    public static String assertion(String sessionId, String customerId, String channel, String deviceId, String sessionKind) {
        Instant now = Instant.now();
        JWTClaimsSet claims = claims(sessionId, customerId, channel, deviceId, sessionKind, now).build();
        return sign(header().build(), claims, KEY);
    }

    public static JWTClaimsSet.Builder claims(String sessionId, String customerId, String channel, String deviceId,
                                              String sessionKind, Instant issuedAt) {
        return new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .audience(BffAssertionVerifier.AUDIENCE)
                .subject(customerId)
                .claim("sid", sessionId)
                .claim("channel", channel)
                .claim("deviceId", deviceId)
                .claim("sessionKind", sessionKind)
                .issueTime(Date.from(issuedAt))
                .expirationTime(Date.from(issuedAt.plusSeconds(30)))
                .jwtID(UUID.randomUUID().toString());
    }

    public static JWSHeader.Builder header() {
        return new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("bff-assertion+jwt"))
                .keyID(KEY_ID);
    }

    public static String sign(JWSHeader header, JWTClaimsSet claims, ECKey signingKey) {
        try {
            SignedJWT assertion = new SignedJWT(header, claims);
            assertion.sign(new ECDSASigner(signingKey));
            return assertion.serialize();
        } catch (JOSEException failure) {
            throw new IllegalStateException(failure);
        }
    }

    private static ECKey generate() {
        try {
            return new ECKeyGenerator(Curve.P_256).keyID(KEY_ID).generate();
        } catch (JOSEException failure) {
            throw new IllegalStateException(failure);
        }
    }
}
