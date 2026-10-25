package com.vpbank.dcp.core.password;

import com.vpbank.dcp.core.device.DeviceStanding;
import com.vpbank.dcp.core.device.DeviceOwnership;
import com.vpbank.dcp.core.device.BindingId;
import com.vpbank.dcp.core.customer.SubjectId;
import com.vpbank.dcp.core.customer.CustomerNumber;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.vpbank.dcp.core.customer.CustomerAuthenticationState;
import com.vpbank.dcp.core.customer.CustomerStatus;
import com.vpbank.dcp.core.security.Digest32;
import com.vpbank.dcp.core.security.RequestKeyThumbprint;
import com.vpbank.dcp.core.session.IssueLoginSessionService;
import com.vpbank.dcp.core.session.LoginConfirmation;
import com.vpbank.dcp.core.session.SessionLoginEvidence;
import com.vpbank.dcp.core.session.SessionLoginResult;
import com.vpbank.dcp.core.device.LoginDeviceSnapshot;
import com.vpbank.dcp.core.device.StoredDeviceKey;
import com.vpbank.dcp.core.security.VerifiedDpopProof;
import com.vpbank.dcp.core.session.PreparedSession;
import com.vpbank.dcp.core.session.RestrictedSessionResult;
import com.vpbank.dcp.core.session.TrustedDeviceSessions;
import com.vpbank.dcp.core.session.LoginKeys;
import com.vpbank.dcp.core.session.PreparedRestrictedSession;
import com.vpbank.dcp.core.session.RestrictedSession;
import com.vpbank.dcp.core.session.TrustTarget;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;

class PasswordLoginServiceTest {
    private final PasswordProofs proofs = mock(PasswordProofs.class);
    private final CustomerIdentities identities = mock(CustomerIdentities.class);
    private final LoginDevices devices = mock(LoginDevices.class);
    private final IssueLoginSessionService sessions = mock(IssueLoginSessionService.class);
    private final TrustedDeviceSessions trustedDevices = mock(TrustedDeviceSessions.class);

    private final Instant now = Instant.parse("2026-10-13T00:00:00Z");
    private final Digest32 digest = Digest32.fromBytes(new byte[32]);
    private final SubjectId subject = new SubjectId(UUID.randomUUID());
    private final UUID generation = UUID.randomUUID();
    private final PasswordLoginCommand command = command();
    private final CustomerAuthenticationState customer =
            new CustomerAuthenticationState(new CustomerNumber("customer-a"), CustomerStatus.ELIGIBLE, 3, 0, now);

    @Test
    void invalidProofDoesNotDispatchPassword() {
        when(proofs.admit(command))
                .thenReturn(new PasswordProofAdmissionResult.Denied(LoginDenial.REJECTED));

        assertThat(service().login(command)).isInstanceOf(PasswordLoginResult.Rejected.class);
        verifyNoInteractions(identities);
        verifyNoInteractions(devices);
    }

    /** A proof outage must stay UNAVAILABLE: answering REJECTED would read as a wrong password. */
    @Test
    void proofOutageIsTemporarilyUnavailableNotRejected() {
        when(proofs.admit(command))
                .thenReturn(new PasswordProofAdmissionResult.Denied(LoginDenial.UNAVAILABLE));

        assertThat(service().login(command))
                .isInstanceOf(PasswordLoginResult.TemporarilyUnavailable.class);
    }

    @Test
    void passwordTimeoutCannotRouteOrIssueSession() {
        admitted();
        when(identities.confirm(command))
                .thenReturn(new PasswordIdentityResult.Denied(LoginDenial.UNAVAILABLE));

        assertThat(service().login(command))
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

        service().login(command);

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

        assertThat(service().login(command)).isEqualTo(new PasswordLoginResult.Active(prepared));

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

        assertThat(service().login(command)).isInstanceOf(PasswordLoginResult.Rejected.class);
    }

    /** A non-primary binding must be trusted again: restricted token only, never ACTIVE. */
    @Test
    void otherTrustedReceivesARestrictedSessionAndNeverAnActiveOne() {
        LoginDeviceSnapshot device = device(false);
        RestrictedSession pinned = restrictedFor(new DeviceTrustResult.OtherTrusted(device));

        assertThat(pinned.device().target()).isEqualTo(new TrustTarget.KnownDevice(device.bindingId(),
                device.deviceKeyThumbprint(), device.securityVersion()));
        assertThat(pinned.customer().owner()).isEqualTo(subject);
        assertThat(pinned.customer().number()).isEqualTo(customer.customerNumber());
        assertThat(pinned.customer().statusVersion()).isEqualTo(customer.statusVersion());
        assertThat(pinned.keys()).isEqualTo(new LoginKeys("request-jwk", digest, "response-jwk"));
        assertThat(pinned.device().platform()).isEqualTo("ANDROID");
        assertThat(pinned.generation()).isEqualTo(generation);
        verify(sessions, never()).issue(any(), any(), any());
    }

    /** A revoked or expired binding keeps its stored key and goes through the same flow. */
    @Test
    void lapsedBindingReceivesARestrictedSessionForTheSameBinding() {
        LoginDeviceSnapshot device = device(true);
        RestrictedSession pinned = restrictedFor(new DeviceTrustResult.Lapsed(device));

        assertThat(pinned.device().target()).isEqualTo(new TrustTarget.KnownDevice(device.bindingId(),
                device.deviceKeyThumbprint(), device.securityVersion()));
        verify(sessions, never()).issue(any(), any(), any());
    }

    @Test
    void newDeviceReceivesARestrictedSessionWithNoBinding() {
        RestrictedSession pinned = restrictedFor(new DeviceTrustResult.NewDevice());

        assertThat(pinned.device().target()).isEqualTo(new TrustTarget.NewDevice());
        verify(sessions, never()).issue(any(), any(), any());
    }

    @Test
    void restrictedSessionThatCannotBeStoredIsTemporarilyUnavailable() {
        admitted();
        verified();
        when(devices.decide(subject, command, verifiedProofs()))
                .thenReturn(new DeviceTrustResult.NewDevice());
        when(trustedDevices.open(any(), any(), any()))
                .thenReturn(new RestrictedSessionResult.Unavailable());

        assertThat(service().login(command))
                .isInstanceOf(PasswordLoginResult.TemporarilyUnavailable.class);
    }

    private RestrictedSession restrictedFor(DeviceTrustResult route) {
        admitted();
        verified();
        when(devices.decide(subject, command, verifiedProofs())).thenReturn(route);
        ArgumentCaptor<RestrictedSession> pinned = ArgumentCaptor.forClass(RestrictedSession.class);
        when(trustedDevices.open(pinned.capture(), eq(command.operation().deviceId()), eq(now)))
                .thenAnswer(call -> new RestrictedSessionResult.Opened(new PreparedRestrictedSession(
                        call.getArgument(0), UUID.randomUUID(),
                        digest, digest,
                        now.plusSeconds(600), "restricted-envelope", "restricted-receipt")));

        assertThat(service().login(command)).isEqualTo(new PasswordLoginResult.NeedTrustedDevice(
                "restricted-envelope", "restricted-receipt", now.plusSeconds(600)));
        return pinned.getValue();
    }

    private void admitted() {
        when(proofs.admit(command)).thenReturn(new PasswordProofAdmissionResult.Admitted(
                new AdmittedProof(verifiedProofs(), generation)));
    }

    private void verified() {
        when(identities.confirm(command))
                .thenReturn(new PasswordIdentityResult.Verified(subject, customer));
    }

    private PasswordLoginService service() {
        return new PasswordLoginService(proofs, identities, devices, sessions, trustedDevices);
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
        return new LoginDeviceSnapshot(new BindingId(UUID.randomUUID()), new DeviceOwnership(subject, "neo-mobile"), "ANDROID",
                true, new DeviceStanding(true, now.plusSeconds(3600), primary), 1,
                new StoredDeviceKey(new byte[]{1}, digest));
    }
}
