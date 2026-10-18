package com.vpbank.dcp.core.application.mfa;

import com.vpbank.dcp.core.domain.customer.CustomerNumber;
import com.vpbank.dcp.core.domain.device.BindingId;
import com.vpbank.dcp.core.domain.customer.SubjectId;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.LookupKeyVersion;
import com.vpbank.dcp.core.domain.security.RequestKeyThumbprint;
import com.vpbank.dcp.core.port.in.mfa.ConfirmLoginCommand;
import com.vpbank.dcp.core.port.out.pending.PendingMfaLogin;
import com.vpbank.dcp.core.port.out.pending.PendingMfaLoginStore;
import com.vpbank.dcp.core.port.out.replay.ReplayProtection;
import com.vpbank.dcp.core.port.out.replay.ReplayReservation;
import com.vpbank.dcp.core.port.out.security.VerifiedDpopProof;
import com.vpbank.dcp.core.port.out.session.SessionTokenLookup;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class AdmitPendingTotpServiceTest {
    private final PendingMfaLoginStore pending = mock(PendingMfaLoginStore.class);
    private final ReplayProtection replay = mock(ReplayProtection.class);
    private final AdmitPendingLoginService service = new AdmitPendingLoginService(pending, replay);
    private final Instant now = Instant.parse("2026-10-13T00:00:00Z");

    @Test
    void matchingPendingAndUniqueDpopAreAdmitted() {
        Fixture fixture = fixture(now.plusSeconds(120), VerifiedDpopProof.Verification.VERIFIED);
        when(pending.find(fixture.command.pendingToken())).thenReturn(Optional.of(fixture.pending));
        when(replay.reserve(any())).thenReturn(ReplayReservation.RESERVED);

        assertThat(service.admit(fixture.command))
                .isEqualTo(new PendingLoginAdmission.Admitted(fixture.pending));
    }

    @Test
    void expiredChallengeAndUnverifiedDpopNeverReserveReplay() {
        Fixture expired = fixture(now, VerifiedDpopProof.Verification.VERIFIED);
        when(pending.find(expired.command.pendingToken())).thenReturn(Optional.of(expired.pending));
        assertThat(service.admit(expired.command)).isInstanceOf(PendingLoginAdmission.Rejected.class);

        Fixture disabled = fixture(now.plusSeconds(120),
                VerifiedDpopProof.Verification.DISABLED_FOR_NON_PRODUCTION);
        when(pending.find(disabled.command.pendingToken())).thenReturn(Optional.of(disabled.pending));
        assertThat(service.admit(disabled.command)).isInstanceOf(PendingLoginAdmission.Rejected.class);
        verify(replay, never()).reserve(any());
    }

    @Test
    void replayedProofCannotVerifyTotp() {
        Fixture fixture = fixture(now.plusSeconds(120), VerifiedDpopProof.Verification.VERIFIED);
        when(pending.find(fixture.command.pendingToken())).thenReturn(Optional.of(fixture.pending));
        when(replay.reserve(any())).thenReturn(ReplayReservation.REPLAYED);

        assertThat(service.admit(fixture.command)).isInstanceOf(PendingLoginAdmission.Rejected.class);
    }

    private Fixture fixture(Instant expiry, VerifiedDpopProof.Verification verification) {
        Digest32 digest = Digest32.fromBytes(new byte[32]);
        var challenge = new PendingMfaLogin.Challenge("QkJCQkJCQkJCQkJCQkJCQg",
                "Q0NDQ0NDQ0NDQ0NDQ0NDQw", expiry);
        var login = new PendingMfaLogin(new PendingMfaLogin.Identity(UUID.randomUUID(),
                new SubjectId(UUID.randomUUID()), new CustomerNumber("customer-a"),
                new BindingId(UUID.randomUUID()), "neo-mobile",
                "installation-1234567890"),
                new PendingMfaLogin.Keys(digest.base64Url(), "request-jwk", "response-jwk",
                        digest.base64Url()), challenge,
                new PendingMfaLogin.Versions(3, 1, UUID.randomUUID()));
        var dpop = new VerifiedDpopProof(new RequestKeyThumbprint(digest), digest,
                now, "request-jwk", verification);
        var token = new SessionTokenLookup(new LookupKeyVersion("v1"), digest);
        return new Fixture(login, new ConfirmLoginCommand(challenge.challengeId(), token,
                dpop, "encrypted-code", now));
    }

    private record Fixture(PendingMfaLogin pending, ConfirmLoginCommand command) { }
}
