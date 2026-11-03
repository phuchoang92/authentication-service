package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.vpbank.dcp.auth.domain.model.ServiceId;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ServiceClientAssertionVerifier.VerifiedClientAssertion;
import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Slice 12: only an exact, current assertion signed with the key pinned for the service it names is accepted. */
class ServiceClientAssertionVerifierTest {
    private static final Instant NOW = Instant.parse("2026-11-03T10:00:00Z");
    private static final ServiceId ONBOARDING_SERVICE = new ServiceId(TestServiceClientAssertions.SERVICE_ID);
    private final ServiceClientAssertionVerifier verifier = new ServiceClientAssertionVerifier(
            Map.of(ONBOARDING_SERVICE, TestServiceClientAssertions.publicKey()), Clock.fixed(NOW, ZoneOffset.UTC));

    @Test
    void aGenuineAssertionNamesItsService() {
        Optional<VerifiedClientAssertion> verified = verifier.verify(sign(header(), claims()));

        assertThat(verified).contains(new VerifiedClientAssertion(ONBOARDING_SERVICE, "jti-1", NOW.plusSeconds(30)));
    }

    @Test
    void theHeaderMustNameTheServicesKeyAndCarryNoKeyMaterial() throws Exception {
        ECKey otherKey = new ECKeyGenerator(Curve.P_256).keyID(TestServiceClientAssertions.KEY_ID).generate();
        assertRejected(TestBffAssertions.sign(header().build(), claims().build(), otherKey));          // not the pinned key
        assertRejected(sign(header().keyID("onboarding-other"), claims()));                             // another key ID
        assertRejected(sign(header().keyID(null), claims()));
        assertRejected(sign(header().type(new JOSEObjectType("bff-assertion+jwt")), claims()));         // the BFF's type
        assertRejected(sign(header().type(null), claims()));
        assertRejected(sign(header().jwk(TestServiceClientAssertions.publicKey()), claims()));          // embedded key
        assertRejected(sign(header().jwkURL(URI.create("https://onboarding.test/jwks")), claims()));    // remote key
        assertRejected(sign(header().x509CertURL(URI.create("https://onboarding.test/cert")), claims()));
        assertRejected(sign(header().criticalParams(Set.of("exp")), claims()));                         // critical extension
        ECKey p384 = new ECKeyGenerator(Curve.P_384).keyID(TestServiceClientAssertions.KEY_ID).generate();
        JWSHeader es384 = new JWSHeader.Builder(JWSAlgorithm.ES384)
                .type(new JOSEObjectType("service-client-assertion+jwt"))
                .keyID(TestServiceClientAssertions.KEY_ID)
                .build();
        assertRejected(TestBffAssertions.sign(es384, claims().build(), p384));                          // not ES256
        assertRejected("not.a.jws");
        assertRejected("");
    }

    @Test
    void theClaimSetMustBeExactAndTheServiceMustBeKnownAndSpeakForItself() {
        assertRejected(sign(header(), claims().claim("scope", "onboarding")));                         // an extra claim
        assertRejected(sign(header(), claims().jwtID(null)));                                           // a missing claim
        assertRejected(sign(header(), claims().issuer("account-service")));                             // iss != sub
        assertRejected(sign(header(), claims().issuer("account-service").subject("account-service")));  // unknown service
        assertRejected(sign(header(), claims().subject("Onboarding Service")));                         // not a service ID
        assertRejected(sign(header(), claims().audience("mobile-bff")));
        assertRejected(sign(header(), claims().jwtID(" ")));
        assertRejected(sign(header(), claims().jwtID("j".repeat(129))));
        assertRejected(sign(header(), claims().claim("sub", 42)));                                      // wrong type
    }

    @Test
    void anAssertionLivesAtMostSixtySecondsWithFiveSecondsOfSkew() {
        assertRejected(sign(header(), claims().expirationTime(Date.from(NOW.plusSeconds(61)))));        // too long-lived
        assertRejected(sign(header(), claims().expirationTime(Date.from(NOW))));                        // exp = iat
        assertRejected(sign(header(), claims().issueTime(Date.from(NOW.minusSeconds(40)))
                .expirationTime(Date.from(NOW.minusSeconds(6)))));                                      // expired
        assertRejected(sign(header(), claims().issueTime(Date.from(NOW.plusSeconds(6)))
                .expirationTime(Date.from(NOW.plusSeconds(30)))));                                      // from the future
        assertRejected(sign(header(), claims().issueTime(null)));

        String withinSkew = sign(header(), claims().issueTime(Date.from(NOW.minusSeconds(30)))
                .expirationTime(Date.from(NOW.minusSeconds(4))));
        assertThat(verifier.verify(withinSkew)).isPresent();
    }

    @Test
    void everyPinnedKeyMustBePublicP256AndNamed() throws Exception {
        Clock clock = Clock.systemUTC();
        assertThatThrownBy(() -> new ServiceClientAssertionVerifier(Map.of(ONBOARDING_SERVICE, TestServiceClientAssertions.KEY), clock))
                .isInstanceOf(IllegalArgumentException.class);
        ECKey unnamed = new ECKeyGenerator(Curve.P_256).generate().toPublicJWK();
        assertThatThrownBy(() -> new ServiceClientAssertionVerifier(Map.of(ONBOARDING_SERVICE, unnamed), clock))
                .isInstanceOf(IllegalArgumentException.class);
        ECKey p384 = new ECKeyGenerator(Curve.P_384).keyID("k").generate().toPublicJWK();
        assertThatThrownBy(() -> new ServiceClientAssertionVerifier(Map.of(ONBOARDING_SERVICE, p384), clock))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(new ServiceClientAssertionVerifier(Map.of(), clock).verify(sign(header(), claims()))).isEmpty();
    }

    private void assertRejected(String assertion) {
        assertThat(verifier.verify(assertion)).isEmpty();
    }

    private static JWSHeader.Builder header() {
        return TestServiceClientAssertions.header();
    }

    private static JWTClaimsSet.Builder claims() {
        return TestServiceClientAssertions.claims(NOW).jwtID("jti-1");
    }

    private static String sign(JWSHeader.Builder header, JWTClaimsSet.Builder claims) {
        return TestBffAssertions.sign(header.build(), claims.build(), TestServiceClientAssertions.KEY);
    }
}
