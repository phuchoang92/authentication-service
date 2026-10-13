package com.vpbank.dcp.core.application.mfa;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.vpbank.dcp.core.domain.customer.CustomerAuthenticationState;
import com.vpbank.dcp.core.domain.customer.CustomerStatus;
import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.LookupKeyVersion;
import com.vpbank.dcp.core.domain.security.RequestKeyThumbprint;
import com.vpbank.dcp.core.port.in.mfa.TotpLoginCommand;
import com.vpbank.dcp.core.port.in.mfa.TotpLoginResult;
import com.vpbank.dcp.core.port.in.session.IssueLoginSessionUseCase;
import com.vpbank.dcp.core.port.in.session.LoginConfirmation;
import com.vpbank.dcp.core.port.in.session.SessionLoginEvidence;
import com.vpbank.dcp.core.port.in.session.SessionLoginResult;
import com.vpbank.dcp.core.port.out.device.LoginDeviceSnapshot;
import com.vpbank.dcp.core.port.out.password.StoredDeviceKey;
import com.vpbank.dcp.core.port.out.pending.PendingTotpLogin;
import com.vpbank.dcp.core.port.out.security.VerifiedDpopProof;
import com.vpbank.dcp.core.port.out.session.PreparedSession;
import com.vpbank.dcp.core.port.out.session.SessionTokenLookup;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class CompleteTotpLoginServiceTest {
    private final AdmitPendingTotpService admission = mock(AdmitPendingTotpService.class);
    private final CheckPendingTotpOwnerService owners = mock(CheckPendingTotpOwnerService.class);
    private final CheckTotpChallengeService codes = mock(CheckTotpChallengeService.class);
    private final IssueLoginSessionUseCase sessions = mock(IssueLoginSessionUseCase.class);
    private final CompleteTotpLoginService service = new CompleteTotpLoginService(
            admission, owners, codes, sessions);
    private final Instant now = Instant.parse("2026-10-13T00:00:00Z");

    @Test
    void validTotpConsumesPendingBeforeActiveSession() {
        Fixture fixture = fixture();
        PreparedSession prepared = mock(PreparedSession.class);
        when(admission.admit(fixture.command)).thenReturn(new PendingTotpAdmission.Admitted(fixture.pending));
        when(owners.current(fixture.pending, now)).thenReturn(fixture.owner);
        when(codes.check(fixture.pending, fixture.command.encryptedCode(), now))
                .thenReturn(TotpChallengeResult.ACCEPTED);
        when(admission.consume(fixture.command.pendingToken(), fixture.pending)).thenReturn(true);
        when(sessions.issue(eq(fixture.pending.identity().operationId()), eq(now),
                any(SessionLoginEvidence.class))).thenReturn(new SessionLoginResult.Active(prepared));

        assertThat(service.complete(fixture.command)).isEqualTo(new TotpLoginResult.Active(prepared));
        org.mockito.ArgumentCaptor<SessionLoginEvidence> evidence =
                org.mockito.ArgumentCaptor.forClass(SessionLoginEvidence.class);
        verify(sessions).issue(eq(fixture.pending.identity().operationId()), eq(now), evidence.capture());
        assertThat(evidence.getValue().confirmation()).isEqualTo(LoginConfirmation.DEVICE_TOTP);
        assertThat(evidence.getValue().keys().requestKey().base64Url())
                .isEqualTo(fixture.pending.keys().requestKeyJkt());
    }

    @Test
    void incorrectCodeRetainsPendingButNeverCreatesSession() {
        Fixture fixture = fixture();
        when(admission.admit(fixture.command)).thenReturn(new PendingTotpAdmission.Admitted(fixture.pending));
        when(owners.current(fixture.pending, now)).thenReturn(fixture.owner);
        when(codes.check(fixture.pending, fixture.command.encryptedCode(), now))
                .thenReturn(TotpChallengeResult.REJECTED);

        assertThat(service.complete(fixture.command)).isInstanceOf(TotpLoginResult.Rejected.class);
        verify(admission, never()).consume(any(), any());
        verify(sessions, never()).issue(any(), any(), any());
    }

    @Test
    void anotherVerifierWinningConsumeCannotCreateSecondSession() {
        Fixture fixture = fixture();
        when(admission.admit(fixture.command)).thenReturn(new PendingTotpAdmission.Admitted(fixture.pending));
        when(owners.current(fixture.pending, now)).thenReturn(fixture.owner);
        when(codes.check(fixture.pending, fixture.command.encryptedCode(), now))
                .thenReturn(TotpChallengeResult.ACCEPTED);
        when(admission.consume(fixture.command.pendingToken(), fixture.pending)).thenReturn(false);

        assertThat(service.complete(fixture.command)).isInstanceOf(TotpLoginResult.Rejected.class);
        verify(sessions, never()).issue(any(), any(), any());
    }

    @Test
    void missingOrExpiredPendingCannotReachTotpVerifier() {
        Fixture fixture = fixture();
        when(admission.admit(fixture.command)).thenReturn(new PendingTotpAdmission.Rejected());

        assertThat(service.complete(fixture.command)).isInstanceOf(TotpLoginResult.Rejected.class);
        verify(codes, never()).check(any(), any(), any());
    }

    private Fixture fixture() {
        UUID customerId = UUID.randomUUID();
        UUID bindingId = UUID.randomUUID();
        Digest32 digest = Digest32.fromBytes(new byte[32]);
        PendingTotpLogin pending = new PendingTotpLogin(
                new PendingTotpLogin.Identity(UUID.randomUUID(), customerId, "customer-a", bindingId,
                        "neo-mobile", "installation-1234567890"),
                new PendingTotpLogin.Keys(digest.base64Url(), "request-jwk", "response-jwk",
                        digest.base64Url()),
                new PendingTotpLogin.Challenge("QkJCQkJCQkJCQkJCQkJCQg", "Q0NDQ0NDQ0NDQ0NDQ0NDQw",
                        now.plusSeconds(120)),
                new PendingTotpLogin.Versions(3, 1, UUID.randomUUID()));
        SessionTokenLookup token = new SessionTokenLookup(new LookupKeyVersion("v1"), digest);
        VerifiedDpopProof dpop = new VerifiedDpopProof(new RequestKeyThumbprint(digest), digest,
                now, "request-jwk");
        TotpLoginCommand command = new TotpLoginCommand(pending.challenge().challengeId(),
                token, dpop, "encrypted-code", now);
        CustomerAuthenticationState customer = new CustomerAuthenticationState("customer-a",
                CustomerStatus.ELIGIBLE, 3, 0, now);
        LoginDeviceSnapshot device = new LoginDeviceSnapshot(bindingId, customerId,
                "neo-mobile", "ANDROID", true, true, false, now.plusSeconds(3600), 1,
                new StoredDeviceKey(new byte[]{1}, digest));
        return new Fixture(command, pending, new PendingTotpOwner.Current(customer, device));
    }

    private record Fixture(TotpLoginCommand command, PendingTotpLogin pending,
                           PendingTotpOwner.Current owner) { }
}
