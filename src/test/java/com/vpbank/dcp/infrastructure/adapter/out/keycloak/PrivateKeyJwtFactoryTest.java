package com.vpbank.dcp.infrastructure.adapter.out.keycloak;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import java.net.URI;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class PrivateKeyJwtFactoryTest {

    private final URI audience = URI.create("https://keycloak.internal/realms/mobile-banking/"
            + "protocol/openid-connect/token");
    private final Instant now = Instant.parse("2026-10-11T03:10:00Z");

    @Test
    void everyMutationReceivesItsOwnShortLivedAssertion() throws Exception {
        var key = new ECKeyGenerator(Curve.P_256).keyID("auth-workload-1").generate();
        var factory = new PrivateKeyJwtFactory("authentication-service", audience, key);
        SignedJWT first = SignedJWT.parse(factory.issue(now));
        SignedJWT second = SignedJWT.parse(factory.issue(now));

        assertTrue(first.verify(new ECDSAVerifier(key.toPublicJWK())));
        assertEquals("authentication-service", first.getJWTClaimsSet().getIssuer());
        assertEquals("authentication-service", first.getJWTClaimsSet().getSubject());
        assertEquals(audience.toString(), first.getJWTClaimsSet().getAudience().getFirst());
        assertEquals(now.plusSeconds(30), first.getJWTClaimsSet().getExpirationTime().toInstant());
        assertNotEquals(first.getJWTClaimsSet().getJWTID(), second.getJWTClaimsSet().getJWTID());
    }

    @Test
    void rejectNonTlsAudience() throws Exception {
        var key = new ECKeyGenerator(Curve.P_256).keyID("auth-workload-1").generate();
        assertThrows(InvalidKeycloakClientConfigurationException.class,
                () -> new PrivateKeyJwtFactory("authentication-service", URI.create("http://keycloak.internal/realms/"
                        + "mobile-banking/protocol/openid-connect/token"), key));
    }
}
