package com.vpbank.dcp.infrastructure.adapter.in.web.mfa;

import com.vpbank.dcp.core.domain.customer.CustomerNumber;
import com.vpbank.dcp.core.domain.device.BindingId;
import com.vpbank.dcp.core.domain.customer.SubjectId;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.LookupKeyVersion;
import com.vpbank.dcp.core.domain.security.RequestKeyThumbprint;
import com.vpbank.dcp.core.port.out.pending.PendingTokenLookup;
import com.vpbank.dcp.core.port.out.pending.PendingMfaLogin;
import com.vpbank.dcp.core.port.out.pending.PendingMfaLoginStore;
import com.vpbank.dcp.core.port.out.security.DpopExpectation;
import com.vpbank.dcp.core.port.out.security.DpopProofDecoder;
import com.vpbank.dcp.core.port.out.security.VerifiedDpopProof;
import com.vpbank.dcp.core.port.out.session.SessionTokenLookup;
import com.vpbank.dcp.infrastructure.adapter.in.web.ExternalUriPolicy;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

class ConfirmLoginRequestVerifierTest {
    private final PendingTokenLookup lookup = mock(PendingTokenLookup.class);
    private final PendingMfaLoginStore pending = mock(PendingMfaLoginStore.class);
    private final DpopProofDecoder dpop = mock(DpopProofDecoder.class);
    private final Instant now = Instant.parse("2026-10-13T00:00:00Z");
    private final ConfirmLoginRequestVerifier verifier = new ConfirmLoginRequestVerifier(lookup, pending,
            dpop, new ExternalUriPolicy("https://api.bank.example"), Clock.fixed(now, ZoneOffset.UTC));

    @Test
    void bindsProofToExactPendingTokenChallengeKeyAndPublicUri() {
        String challengeId = "Q0NDQ0NDQ0NDQ0NDQ0NDQw";
        String token = "v1." + "A".repeat(43);
        Digest32 digest = Digest32.fromBytes(new byte[32]);
        SessionTokenLookup key = new SessionTokenLookup(new LookupKeyVersion("v1"), digest);
        PendingMfaLogin login = pending(challengeId, digest);
        VerifiedDpopProof verified = new VerifiedDpopProof(new RequestKeyThumbprint(digest),
                digest, now, "request-jwk");
        when(lookup.forExactToken(token)).thenReturn(key);
        when(pending.find(key)).thenReturn(Optional.of(login));
        when(dpop.verify(any(), any())).thenReturn(verified);

        var result = verifier.verify(challengeId, "DPoP " + token, "B".repeat(64), "encrypted-code");
        assertThat(result.pendingToken()).isEqualTo(key);
        assertThat(result.dpop()).isEqualTo(verified);
        ArgumentCaptor<DpopExpectation> expectation = ArgumentCaptor.forClass(DpopExpectation.class);
        verify(dpop).verify(org.mockito.ArgumentMatchers.eq("B".repeat(64)), expectation.capture());
        assertThat(expectation.getValue().externalUri().toASCIIString())
                .isEqualTo("https://api.bank.example/api/mfa/challenges/" + challengeId + "/verify");
        assertThat(expectation.getValue().nonce()).isEqualTo(challengeId);
        assertThat(expectation.getValue().exactToken()).isEqualTo(token);
        assertThat(expectation.getValue().requestKey()).isEqualTo(new RequestKeyThumbprint(digest));
    }

    @Test
    void wrongChallengeCannotReachDpopDecoderOrTotpCode() {
        String challengeId = "Q0NDQ0NDQ0NDQ0NDQ0NDQw";
        String token = "v1." + "A".repeat(43);
        SessionTokenLookup key = new SessionTokenLookup(new LookupKeyVersion("v1"),
                Digest32.fromBytes(new byte[32]));
        when(lookup.forExactToken(token)).thenReturn(key);
        when(pending.find(key)).thenReturn(Optional.of(pending("RERERERERERERERERERERA",
                Digest32.fromBytes(new byte[32]))));

        assertThatThrownBy(() -> verifier.verify(challengeId, "DPoP " + token,
                "B".repeat(64), "encrypted-code"))
                .isInstanceOf(InvalidConfirmLoginRequestException.class);
        verify(dpop, never()).verify(any(), any());
    }

    private PendingMfaLogin pending(String challengeId, Digest32 digest) {
        return new PendingMfaLogin(new PendingMfaLogin.Identity(UUID.randomUUID(),
                new SubjectId(UUID.randomUUID()), new CustomerNumber("customer-a"),
                new BindingId(UUID.randomUUID()), "neo-mobile",
                "installation-1234567890"),
                new PendingMfaLogin.Keys(digest.base64Url(), "request-jwk", "response-jwk",
                        digest.base64Url()),
                new PendingMfaLogin.Challenge("QkJCQkJCQkJCQkJCQkJCQg", challengeId,
                        now.plusSeconds(120)),
                new PendingMfaLogin.Versions(3, 1, UUID.randomUUID()));
    }
}
