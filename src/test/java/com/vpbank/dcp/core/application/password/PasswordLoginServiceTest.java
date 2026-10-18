package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.domain.device.BindingId;
import com.vpbank.dcp.core.domain.customer.SubjectId;
import com.vpbank.dcp.core.domain.customer.CustomerNumber;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.vpbank.dcp.core.domain.customer.CustomerAuthenticationState;
import com.vpbank.dcp.core.domain.customer.CustomerStatus;
import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.RequestKeyThumbprint;
import com.vpbank.dcp.core.port.in.password.PasswordLoginCommand;
import com.vpbank.dcp.core.port.in.password.PasswordLoginResult;
import com.vpbank.dcp.core.port.in.session.IssueLoginSessionUseCase;
import com.vpbank.dcp.core.port.in.session.LoginConfirmation;
import com.vpbank.dcp.core.port.in.session.SessionLoginEvidence;
import com.vpbank.dcp.core.port.in.session.SessionLoginResult;
import com.vpbank.dcp.core.port.out.device.LoginDeviceSnapshot;
import com.vpbank.dcp.core.port.out.credential.PasswordVerification;
import com.vpbank.dcp.core.port.out.password.PasswordOperationContext;
import com.vpbank.dcp.core.port.out.password.PasswordProofIds;
import com.vpbank.dcp.core.port.out.password.PasswordWireProofs;
import com.vpbank.dcp.core.port.out.password.StoredDeviceKey;
import com.vpbank.dcp.core.port.out.password.VerifiedPasswordProofs;
import com.vpbank.dcp.core.port.out.security.VerifiedDpopProof;
import com.vpbank.dcp.core.port.out.session.PreparedSession;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;

class PasswordLoginServiceTest {
    private final PasswordProofs proofs = mock(PasswordProofs.class);
    private final CustomerIdentities identities = mock(CustomerIdentities.class);
    private final LoginDevices devices = mock(LoginDevices.class);
    private final IssueLoginSessionUseCase sessions = mock(IssueLoginSessionUseCase.class);

    private final Instant now = Instant.parse("2026-10-13T00:00:00Z");
    private final Digest32 digest = Digest32.fromBytes(new byte[32]);
    private final SubjectId subject = new SubjectId(UUID.randomUUID());
    private final UUID generation = UUID.randomUUID();
    private final PasswordLoginCommand command = command();
    private final CustomerAuthenticationState customer =
            new CustomerAuthenticationState(new CustomerNumber("customer-a"), CustomerStatus.ELIGIBLE, 3, 0, now);

    @Test
    void productionGateNeverDispatchesPassword() {
        assertThat(service(false).login(command))
                .isInstanceOf(PasswordLoginResult.TemporarilyUnavailable.class);
        verifyNoInteractions(proofs);
        verifyNoInteractions(identities);
    }

    @Test
    void invalidProofDoesNotDispatchPassword() {
        when(proofs.admit(command))
                .thenReturn(new PasswordProofAdmissionResult.Denied(LoginDenial.REJECTED));

        assertThat(service(true).login(command)).isInstanceOf(PasswordLoginResult.Rejected.class);
        verifyNoInteractions(identities);
        verifyNoInteractions(devices);
    }

    /** A proof outage must stay UNAVAILABLE: answering REJECTED would read as a wrong password. */
    @Test
    void proofOutageIsTemporarilyUnavailableNotRejected() {
        when(proofs.admit(command))
                .thenReturn(new PasswordProofAdmissionResult.Denied(LoginDenial.UNAVAILABLE));

        assertThat(service(true).login(command))
                .isInstanceOf(PasswordLoginResult.TemporarilyUnavailable.class);
    }

    @Test
    void passwordTimeoutCannotRouteOrIssueSession() {
        admitted();
        when(identities.confirm(command))
                .thenReturn(new PasswordIdentityResult.Denied(LoginDenial.UNAVAILABLE));

        assertThat(service(true).login(command))
                .isInstanceOf(PasswordLoginResult.TemporarilyUnavailable.class);
        verifyNoInteractions(devices);
        verify(sessions, never()).issue(any(), any(), any());
    }

    /** Replay markers must be reserved before the password can reach Keycloak. */
    @Test
    void replayMarkersAreReservedBeforeTheCredentialIsVerified() {
        admitted();
        when(identities.confirm(command))
                .thenReturn(new PasswordIdentityResult.Denied(LoginDenial.REJECTED));

        service(true).login(command);

        InOrder order = inOrder(proofs, identities);
        order.verify(proofs).admit(command);
        order.verify(identities).confirm(command);
    }

    @Test
    void primaryTrustedCanReceiveRealPreparedSession() {
        PreparedSession prepared = mock(PreparedSession.class);
        admitted();
        verified();
        when(devices.decide(subject, command, verifiedProofs()))
                .thenReturn(new DeviceTrustResult.LastTrusted(device(true)));
        when(sessions.issue(eq(command.operation().operationId()), eq(now),
                any(SessionLoginEvidence.class)))
                .thenReturn(new SessionLoginResult.Active(prepared));

        assertThat(service(true).login(command)).isEqualTo(new PasswordLoginResult.Active(prepared));

        ArgumentCaptor<SessionLoginEvidence> captured =
                ArgumentCaptor.forClass(SessionLoginEvidence.class);
        verify(sessions).issue(eq(command.operation().operationId()), eq(now), captured.capture());
        assertThat(captured.getValue().confirmation()).isEqualTo(LoginConfirmation.PRIMARY_PASSWORD);
        assertThat(captured.getValue().keys().deviceKey())
                .isEqualTo(verifiedProofs().deviceKeyThumbprint());
        assertThat(captured.getValue().generation()).isEqualTo(generation);
    }

    @Test
    void rejectedSessionIssuanceIsNotReportedAsAvailable() {
        admitted();
        verified();
        when(devices.decide(subject, command, verifiedProofs()))
                .thenReturn(new DeviceTrustResult.LastTrusted(device(true)));
        when(sessions.issue(any(), any(), any())).thenReturn(new SessionLoginResult.Rejected());

        assertThat(service(true).login(command)).isInstanceOf(PasswordLoginResult.Rejected.class);
    }

    /**
     * Flow 01: a non-primary trusted device fails closed with START_NEW_LOGIN until the
     * trusted-device continuation has an approved contract. It must never become ACTIVE.
     */
    @Test
    void otherTrustedFailsClosedAndNeverIssuesASession() {
        admitted();
        verified();
        when(devices.decide(subject, command, verifiedProofs()))
                .thenReturn(new DeviceTrustResult.OtherTrusted(device(false)));

        assertThat(service(true).login(command))
                .isInstanceOf(PasswordLoginResult.TemporarilyUnavailable.class);
        verify(sessions, never()).issue(any(), any(), any());
    }

    @Test
    void newDeviceCannotReceiveActiveWithoutMfa() {
        admitted();
        verified();
        when(devices.decide(subject, command, verifiedProofs()))
                .thenReturn(new DeviceTrustResult.NewDevice());

        assertThat(service(true).login(command))
                .isInstanceOf(PasswordLoginResult.TemporarilyUnavailable.class);
        verify(sessions, never()).issue(any(), any(), any());
    }

    private void admitted() {
        when(proofs.admit(command)).thenReturn(new PasswordProofAdmissionResult.Admitted(
                new AdmittedProof(verifiedProofs(), generation)));
    }

    private void verified() {
        when(identities.confirm(command))
                .thenReturn(new PasswordIdentityResult.Verified(subject, customer));
    }

    private PasswordLoginService service(boolean enabled) {
        return new PasswordLoginService(proofs, identities, devices, sessions,
                new PasswordAvailabilityPolicy(enabled));
    }

    private PasswordLoginCommand command() {
        Digest32 d = Digest32.fromBytes(new byte[32]);
        VerifiedDpopProof dpop = new VerifiedDpopProof(new RequestKeyThumbprint(d), d, now,
                "request-jwk");
        return new PasswordLoginCommand(new PasswordOperationContext(UUID.randomUUID(),
                "neo-mobile", "ANDROID", "installation-1234567890", "alice",
                "QkJCQkJCQkJCQkJCQkJCQg"),
                new PasswordVerification("alice", "secret"),
                new PasswordWireProofs(dpop, "request-proof", "device-proof", "response-jwk"),
                now, now.plusSeconds(8), now.plusSeconds(900));
    }

    private VerifiedPasswordProofs verifiedProofs() {
        return new VerifiedPasswordProofs(new RequestKeyThumbprint(digest), digest, digest,
                new PasswordProofIds(digest, digest, digest), "request-jwk", "response-jwk");
    }

    private LoginDeviceSnapshot device(boolean primary) {
        return new LoginDeviceSnapshot(new BindingId(UUID.randomUUID()), subject, "neo-mobile", "ANDROID",
                true, true, primary, now.plusSeconds(3600), 1,
                new StoredDeviceKey(new byte[]{1}, digest));
    }
}
