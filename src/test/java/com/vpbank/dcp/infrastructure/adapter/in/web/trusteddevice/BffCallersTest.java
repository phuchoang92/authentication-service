package com.vpbank.dcp.infrastructure.adapter.in.web.trusteddevice;

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
import com.vpbank.dcp.infrastructure.adapter.out.crypto.BffAssertionVerifier;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.Sha256Digests;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.StrictJoseJson;
import java.time.Instant;
import java.util.Date;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;

class BffCallersTest {
    private static final Instant NOW = Instant.parse("2026-10-18T00:00:00Z");
    private final AssertionReplay replay = mock(AssertionReplay.class);
    private final ECKey bffKey;
    private final BffCallers callers;

    BffCallersTest() throws Exception {
        bffKey = new ECKeyGenerator(Curve.P_256).keyID("bff-v1").generate();
        callers = new BffCallers(new BffAssertionVerifier("mobile-bff", "bff-v1",
                bffKey.toPublicJWK(), new StrictJoseJson(), new Sha256Digests()), replay);
    }

    @Test
    void firstUseOfAValidAssertionNamesTheCaller() throws Exception {
        when(replay.reserve(any(), any())).thenReturn(ReplayReservation.RESERVED);

        TrustedDeviceCaller caller = callers.require(bearer(assertion()), NOW);

        assertThat(caller.channel()).isEqualTo("neo-mobile");
        assertThat(caller.deviceId()).isEqualTo("device-id-1234567890");
        assertThat(caller.session().digest()).isEqualTo(Digest32.fromBytes(new byte[32]));
        verify(replay).reserve(new Sha256Digests().ofProofId("jti-1"), NOW.plusSeconds(30));
    }

    /** One assertion authorizes one step; a captured one cannot drive the next. */
    @Test
    void replayedAssertionIsRejected() throws Exception {
        when(replay.reserve(any(), any())).thenReturn(ReplayReservation.REPLAYED);

        assertThatThrownBy(() -> callers.require(bearer(assertion()), NOW))
                .isInstanceOf(RejectedBffCallerException.class);
    }

    @Test
    void closedReplayAuthorityIsUnavailableNotAFirstUse() throws Exception {
        when(replay.reserve(any(), any())).thenReturn(ReplayReservation.AUTHORITY_CLOSED);

        assertThatThrownBy(() -> callers.require(bearer(assertion()), NOW))
                .isInstanceOf(ReplayAuthorityUnavailableException.class);
    }

    @Test
    void anythingButOneBearerAssertionIsRejectedBeforeReplay() throws Exception {
        String valid = assertion();
        HttpHeaders missing = new HttpHeaders();
        HttpHeaders twice = new HttpHeaders();
        twice.add(HttpHeaders.AUTHORIZATION, "Bearer " + valid);
        twice.add(HttpHeaders.AUTHORIZATION, "Bearer " + valid);
        HttpHeaders basic = new HttpHeaders();
        basic.add(HttpHeaders.AUTHORIZATION, "Basic " + valid);
        HttpHeaders withDpop = bearer(valid);
        withDpop.add("DPoP", "proof");
        HttpHeaders unsigned = bearer(valid.substring(0, valid.lastIndexOf('.') + 1));

        for (HttpHeaders headers : new HttpHeaders[] {missing, twice, basic, withDpop, unsigned,
                bearer("x".repeat(5000))}) {
            assertThatThrownBy(() -> callers.require(headers, NOW))
                    .isInstanceOf(RejectedBffCallerException.class);
        }
        verify(replay, never()).reserve(any(), any());
    }

    private static HttpHeaders bearer(String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION, "Bearer " + token);
        return headers;
    }

    private String assertion() throws Exception {
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("bff-v1")
                .type(new JOSEObjectType("bff-assertion+jwt")).build(),
                new JWTClaimsSet.Builder().issuer("mobile-bff").audience("authentication-service")
                        .claim("sid", "k1:" + Digest32.fromBytes(new byte[32]).base64Url())
                        .claim("channel", "neo-mobile").claim("deviceId", "device-id-1234567890")
                        .issueTime(Date.from(NOW)).expirationTime(Date.from(NOW.plusSeconds(30)))
                        .jwtID("jti-1").build());
        jwt.sign(new ECDSASigner(bffKey));
        return jwt.serialize();
    }
}
