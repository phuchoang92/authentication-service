package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

/** Plays an internal service (the onboarding service) in tests: one test key and well-formed client assertions (slice 12). */
public final class TestServiceClientAssertions {
    public static final String SERVICE_ID = "onboarding-service";
    public static final String KEY_ID = "onboarding-test-1";
    public static final ECKey KEY = generate();

    private TestServiceClientAssertions() {
    }

    /** The public half, as the {@code auth.service-token.callers.<id>.public-jwk} setting carries it. */
    public static String publicJwk() {
        return KEY.toPublicJWK().toJSONString();
    }

    public static ECKey publicKey() {
        return KEY.toPublicJWK();
    }

    /** A fresh, current assertion from the onboarding service; a new {@code jti} each time. */
    public static String assertion() {
        return TestBffAssertions.sign(header().build(), claims(Instant.now()).build(), KEY);
    }

    public static JWTClaimsSet.Builder claims(Instant issuedAt) {
        return new JWTClaimsSet.Builder()
                .issuer(SERVICE_ID)
                .subject(SERVICE_ID)
                .audience(ServiceClientAssertionVerifier.AUDIENCE)
                .issueTime(Date.from(issuedAt))
                .expirationTime(Date.from(issuedAt.plusSeconds(30)))
                .jwtID(UUID.randomUUID().toString());
    }

    public static JWSHeader.Builder header() {
        return new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("service-client-assertion+jwt"))
                .keyID(KEY_ID);
    }

    private static ECKey generate() {
        try {
            return new ECKeyGenerator(Curve.P_256).keyID(KEY_ID).generate();
        } catch (JOSEException failure) {
            throw new IllegalStateException(failure);
        }
    }
}
