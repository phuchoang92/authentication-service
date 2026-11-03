package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.SessionStatus;
import com.vpbank.dcp.auth.domain.model.AdmittedSession;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.SessionId;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.BffAssertionVerifier.VerifiedAssertion;
import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/** DD 20 §6a + slice 11: only an exact, current assertion from the pinned BFF key admits a session. */
class BffAssertionVerifierTest {
    private static final Instant NOW = Instant.parse("2026-11-03T10:00:00Z");
    private static final String SESSION_ID = "00000000-0000-4000-8000-000000000003";
    private final BffAssertionVerifier verifier = new BffAssertionVerifier(TestBffAssertions.publicKey(),
            TestBffAssertions.ISSUER, Clock.fixed(NOW, ZoneOffset.UTC));

    @Test
    void aGenuineAssertionAdmitsTheSessionItNames() {
        String assertion = sign(header(), claims());

        Optional<VerifiedAssertion> verified = verifier.verify(assertion);

        assertThat(verified).isPresent();
        assertThat(verified.get().admittedSession()).isEqualTo(new AdmittedSession(
                new SessionId(UUID.fromString(SESSION_ID)), new CustomerId("90359"), Channel.MOBILE,
                new DeviceId("tablet-2"), SessionStatus.NEED_TRUSTED_DEVICE));
        assertThat(verified.get().assertionId()).isEqualTo("jti-1");
        assertThat(verified.get().expiresAt()).isEqualTo(NOW.plusSeconds(30));
    }

    @Test
    void theHeaderMustNameThePinnedKeyAndCarryNoKeyMaterial() throws Exception {
        ECKey otherKey = new ECKeyGenerator(Curve.P_256).keyID(TestBffAssertions.KEY_ID).generate();
        assertRejected(TestBffAssertions.sign(header().build(), claims().build(), otherKey));          // not the pinned key
        assertRejected(sign(header().keyID("bff-other"), claims()));                                   // another key ID
        assertRejected(sign(header().keyID(null), claims()));                                          // no key ID
        assertRejected(sign(header().type(new JOSEObjectType("JWT")), claims()));                      // not the assertion type
        assertRejected(sign(header().type(null), claims()));
        assertRejected(sign(header().jwk(TestBffAssertions.publicKey()), claims()));                   // embedded key
        assertRejected(sign(header().jwkURL(URI.create("https://bff.test/jwks")), claims()));          // remote key
        assertRejected(sign(header().x509CertURL(URI.create("https://bff.test/cert")), claims()));
        assertRejected(sign(header().criticalParams(Set.of("exp")), claims()));                        // critical extension
        ECKey p384 = new ECKeyGenerator(Curve.P_384).keyID(TestBffAssertions.KEY_ID).generate();
        JWSHeader es384 = new JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.ES384)
                .type(new JOSEObjectType("bff-assertion+jwt"))
                .keyID(TestBffAssertions.KEY_ID)
                .build();
        assertRejected(TestBffAssertions.sign(es384, claims().build(), p384));                         // not ES256
        assertRejected("not.a.jws");
        assertRejected("");
    }

    @Test
    void theClaimSetMustBeExactAndAddressedToAuthByTheBff() {
        assertRejected(sign(header(), claims().claim("scope", "all")));                                // an extra claim
        assertRejected(sign(header(), claims().claim("sessionKind", null)));                           // a missing claim
        assertRejected(sign(header(), claims().issuer("someone-else")));
        assertRejected(sign(header(), claims().audience("another-service")));
        assertRejected(sign(header(), claims().jwtID(" ")));
        assertRejected(sign(header(), claims().jwtID("j".repeat(129))));
    }

    @Test
    void everyIdentifyingClaimMustBeAValidValue() {
        assertRejected(sign(header(), claims().claim("sid", "not-a-uuid")));
        assertRejected(sign(header(), claims().subject("with space")));
        assertRejected(sign(header(), claims().claim("channel", "FAX")));
        assertRejected(sign(header(), claims().claim("deviceId", "")));
        assertRejected(sign(header(), claims().claim("sessionKind", "ENDED")));                        // never admitted
        assertRejected(sign(header(), claims().claim("sessionKind", "SUPERUSER")));
        assertRejected(sign(header(), claims().claim("sid", 42)));                                     // wrong type

        String active = sign(header(), claims().claim("sessionKind", "ACTIVE"));
        assertThat(verifier.verify(active)).map(verified -> verified.admittedSession().full()).contains(true);
    }

    @Test
    void anAssertionLivesAtMostSixtySecondsWithFiveSecondsOfSkew() {
        assertRejected(sign(header(), claims().expirationTime(Date.from(NOW.plusSeconds(61)))));       // too long-lived
        assertRejected(sign(header(), claims().expirationTime(Date.from(NOW))));                       // exp = iat
        assertRejected(sign(header(), claims().issueTime(Date.from(NOW.minusSeconds(40)))
                .expirationTime(Date.from(NOW.minusSeconds(6)))));                                     // expired
        assertRejected(sign(header(), claims().issueTime(Date.from(NOW.plusSeconds(6)))
                .expirationTime(Date.from(NOW.plusSeconds(30)))));                                     // from the future
        assertRejected(sign(header(), claims().issueTime(null)));

        String withinSkew = sign(header(), claims().issueTime(Date.from(NOW.minusSeconds(30)))
                .expirationTime(Date.from(NOW.minusSeconds(4))));
        assertThat(verifier.verify(withinSkew)).isPresent();
    }

    @Test
    void thePinnedKeyMustBePublicAndNamed() throws Exception {
        assertThatThrownBy(() -> new BffAssertionVerifier(TestBffAssertions.KEY, TestBffAssertions.ISSUER, Clock.systemUTC()))
                .isInstanceOf(IllegalArgumentException.class);
        ECKey unnamed = new ECKeyGenerator(Curve.P_256).generate().toPublicJWK();
        assertThatThrownBy(() -> new BffAssertionVerifier(unnamed, TestBffAssertions.ISSUER, Clock.systemUTC()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private void assertRejected(String assertion) {
        assertThat(verifier.verify(assertion)).isEmpty();
    }

    private static JWSHeader.Builder header() {
        return TestBffAssertions.header();
    }

    private static JWTClaimsSet.Builder claims() {
        return TestBffAssertions.claims(SESSION_ID, "90359", "MOBILE", "tablet-2", "NEED_TRUSTED_DEVICE", NOW)
                .jwtID("jti-1");
    }

    private static String sign(JWSHeader.Builder header, JWTClaimsSet.Builder claims) {
        return TestBffAssertions.sign(header.build(), claims.build(), TestBffAssertions.KEY);
    }
}
