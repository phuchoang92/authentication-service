package com.vpbank.dcp.infrastructure.adapter.out.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.port.in.trusteddevice.TrustedDeviceCaller;
import com.vpbank.dcp.core.port.out.replay.AssertionReplay;
import com.vpbank.dcp.core.port.out.replay.ReplayAuthorityUnavailableException;
import com.vpbank.dcp.core.port.out.replay.ReplayReservation;
import java.net.URI;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class BffAssertionVerifierTest {
    private static final Instant NOW = Instant.parse("2026-10-18T00:00:00Z");
    private static final String SID = "abcdef12-3456-4789-8abc-def012345678";
    private final AssertionReplay replay = mock(AssertionReplay.class);
    private final ECKey bffKey;
    private final BffAssertionVerifier verifier;

    BffAssertionVerifierTest() throws Exception {
        bffKey = new ECKeyGenerator(Curve.P_256).keyID("bff-v1").generate();
        verifier = new BffAssertionVerifier("mobile-bff", "bff-v1", bffKey.toPublicJWK(),
                new StrictJoseJson(), new Sha256Digests(), replay);
    }

    @Test
    void firstUseOfAValidAssertionNamesTheCaller() throws Exception {
        when(replay.reserve(any(), any())).thenReturn(ReplayReservation.RESERVED);

        TrustedDeviceCaller caller = verifier.accept(sign(header(), claims()), NOW).orElseThrow();

        assertThat(caller.channel()).isEqualTo("neo-mobile");
        assertThat(caller.deviceId()).isEqualTo("device-id-1234567890");
        verify(replay).reserve(new Sha256Digests().ofProofId("jti-1"), NOW.plusSeconds(30));
    }

    /** One assertion authorizes one step; a captured one cannot drive the next. */
    @Test
    void replayedAssertionIsNotACaller() throws Exception {
        when(replay.reserve(any(), any())).thenReturn(ReplayReservation.REPLAYED);

        assertThat(verifier.accept(sign(header(), claims()), NOW)).isEmpty();
    }

    @Test
    void closedReplayAuthorityIsUnavailableNotAFirstUse() throws Exception {
        when(replay.reserve(any(), any())).thenReturn(ReplayReservation.AUTHORITY_CLOSED);
        String assertion = sign(header(), claims());

        assertThatThrownBy(() -> verifier.accept(assertion, NOW))
                .isInstanceOf(ReplayAuthorityUnavailableException.class);
    }

    /** An invalid assertion never spends a replay marker. */
    @Test
    void invalidAssertionIsNotACallerAndIsNotRecorded() throws Exception {
        assertThat(verifier.accept(sign(header().keyID("bff-v2"), claims()), NOW)).isEmpty();
        verify(replay, never()).reserve(any(), any());
    }

    @Test
    void acceptsTheExactAssertion() throws Exception {
        VerifiedBffAssertion verified = verifier.verify(sign(header(), claims()), NOW);

        assertThat(verified.sessionId()).isEqualTo(UUID.fromString(SID));
        assertThat(verified.channel()).isEqualTo("neo-mobile");
        assertThat(verified.deviceId()).isEqualTo("device-id-1234567890");
        assertThat(verified.expiresAt()).isEqualTo(NOW.plusSeconds(30));
        assertThat(verified.assertionIdDigest()).isEqualTo(new Sha256Digests().ofProofId("jti-1"));
    }

    @Test
    void anotherKeyIsRejected() throws Exception {
        ECKey attacker = new ECKeyGenerator(Curve.P_256).keyID("bff-v1").generate();
        SignedJWT forged = new SignedJWT(header().build(), claims().build());
        forged.sign(new ECDSASigner(attacker));

        rejected(forged.serialize());
    }

    /** A key carried inside the token must never be used to verify it. */
    @Test
    void embeddedKeyIsRejectedEvenWhenItIsThePinnedOne() throws Exception {
        rejected(sign(header().jwk(bffKey.toPublicJWK()), claims()));
        rejected(sign(header().jwkURL(URI.create("https://evil.test/jwks")), claims()));
    }

    /** Without explicit typing, any other JWT the BFF signs could be replayed here. */
    @Test
    void missingOrWrongTypeIsRejected() throws Exception {
        rejected(sign(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("bff-v1"), claims()));
        rejected(sign(header().type(new JOSEObjectType("JWT")), claims()));
    }

    @Test
    void wrongKeyIdIsRejected() throws Exception {
        rejected(sign(header().keyID("bff-v2"), claims()));
    }

    @Test
    void wrongIssuerOrAudienceIsRejected() throws Exception {
        rejected(sign(header(), claims().issuer("other-bff")));
        rejected(sign(header(), claims().audience("other-service")));
        rejected(sign(header(), claims().audience(java.util.List.of("authentication-service", "x"))));
    }

    /** Exact claim set: an extra claim is as wrong as a missing one. */
    @Test
    void extraOrMissingClaimIsRejected() throws Exception {
        rejected(sign(header(), claims().claim("scope", "banking")));
        rejected(sign(header(), without(claims(), "deviceId")));
        rejected(sign(header(), without(claims(), "jti")));
        rejected(sign(header(), without(claims(), "sid")));
    }

    @Test
    void expiredFutureOrOverlyLongAssertionIsRejected() throws Exception {
        rejected(sign(header(), claims().expirationTime(Date.from(NOW))));
        rejected(sign(header(), claims().issueTime(Date.from(NOW.plusSeconds(10)))
                .expirationTime(Date.from(NOW.plusSeconds(40)))));
        rejected(sign(header(), claims().issueTime(Date.from(NOW.minusSeconds(1)))
                .expirationTime(Date.from(NOW.plusSeconds(60)))));
    }

    @Test
    void malformedSessionReferenceIsRejected() throws Exception {
        rejected(sign(header(), claims().claim("sid", "not-a-session-id")));
        rejected(sign(header(), claims().claim("sid", SID.toUpperCase())));
        rejected(sign(header(), claims().claim("sid", "k1:" + Digest32.fromBytes(new byte[32]).base64Url())));
        rejected(sign(header(), claims().claim("deviceId", "short")));
    }

    private void rejected(String compact) {
        assertThatThrownBy(() -> verifier.verify(compact, NOW))
                .isInstanceOf(InvalidCryptographicInputException.class);
    }

    private JWSHeader.Builder header() {
        return new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("bff-v1")
                .type(new JOSEObjectType("bff-assertion+jwt"));
    }

    private JWTClaimsSet.Builder claims() {
        return new JWTClaimsSet.Builder().issuer("mobile-bff").audience("authentication-service")
                .claim("sid", SID).claim("channel", "neo-mobile")
                .claim("deviceId", "device-id-1234567890")
                .issueTime(Date.from(NOW)).expirationTime(Date.from(NOW.plusSeconds(30)))
                .jwtID("jti-1");
    }

    private static JWTClaimsSet.Builder without(JWTClaimsSet.Builder builder, String name) {
        JWTClaimsSet.Builder copy = new JWTClaimsSet.Builder();
        builder.build().getClaims().forEach((key, value) -> {
            if (!key.equals(name)) {
                copy.claim(key, value);
            }
        });
        return copy;
    }

    private String sign(JWSHeader.Builder header, JWTClaimsSet.Builder claims) throws Exception {
        SignedJWT jwt = new SignedJWT(header.build(), claims.build());
        jwt.sign(new ECDSASigner(bffKey));
        return jwt.serialize();
    }
}
