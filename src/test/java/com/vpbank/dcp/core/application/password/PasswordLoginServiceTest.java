package com.vpbank.dcp.core.application.password;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.vpbank.dcp.core.port.in.session.IssueLoginSessionUseCase;
import com.vpbank.dcp.core.port.in.session.LoginConfirmation;
import com.vpbank.dcp.core.port.in.session.SessionLoginEvidence;
import com.vpbank.dcp.core.port.in.session.SessionLoginResult;
import com.vpbank.dcp.core.domain.customer.CustomerAuthenticationState;
import com.vpbank.dcp.core.domain.customer.CustomerStatus;
import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.RequestKeyThumbprint;
import com.vpbank.dcp.core.port.in.password.PasswordLoginCommand;
import com.vpbank.dcp.core.port.in.password.PasswordLoginResult;
import com.vpbank.dcp.core.port.out.device.LoginDeviceSnapshot;
import com.vpbank.dcp.core.port.out.keycloak.PasswordVerification;
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

class PasswordLoginServiceTest {
    private final AssessPasswordLoginService assessments = mock(AssessPasswordLoginService.class);
    private final IssueLoginSessionUseCase sessions = mock(IssueLoginSessionUseCase.class);
    private final StartTotpLoginService totp = mock(StartTotpLoginService.class);
    private final Instant now = Instant.parse("2026-10-13T00:00:00Z");

    @Test
    void productionGateNeverDispatchesPassword() {
        PasswordLoginCommand command = command();
        PasswordLoginService service = service(false);

        assertThat(service.login(command)).isInstanceOf(PasswordLoginResult.TemporarilyUnavailable.class);
        verify(assessments, never()).assess(any());
    }

    @Test
    void primaryTrustedCanReceiveRealPreparedSession() {
        PasswordLoginCommand command = command();
        Fixture fixture = fixture(true);
        PreparedSession prepared = mock(PreparedSession.class);
        when(assessments.assess(command)).thenReturn(new PasswordLoginAssessment.LastTrusted(
                fixture.customerId, fixture.customer, fixture.device, fixture.proofs, fixture.generation));
        when(sessions.issue(eq(command.operation().operationId()), eq(now), any(SessionLoginEvidence.class)))
                .thenReturn(new SessionLoginResult.Active(prepared));

        assertThat(service(true).login(command)).isEqualTo(new PasswordLoginResult.Active(prepared));
        org.mockito.ArgumentCaptor<SessionLoginEvidence> captured =
                org.mockito.ArgumentCaptor.forClass(SessionLoginEvidence.class);
        verify(sessions).issue(eq(command.operation().operationId()), eq(now), captured.capture());
        assertThat(captured.getValue().confirmation()).isEqualTo(LoginConfirmation.PRIMARY_PASSWORD);
        assertThat(captured.getValue().keys().deviceKey()).isEqualTo(fixture.proofs.deviceKeyThumbprint());
    }

    @Test
    void newDeviceCannotReceiveActiveWithoutMfa() {
        PasswordLoginCommand command = command();
        Fixture fixture = fixture(false);
        when(assessments.assess(command)).thenReturn(new PasswordLoginAssessment.NewDevice(
                fixture.customerId, fixture.customer, fixture.proofs, fixture.generation));

        assertThat(service(true).login(command)).isInstanceOf(PasswordLoginResult.TemporarilyUnavailable.class);
        verify(sessions, never()).issue(any(), any(), any());
        verify(totp, never()).start(any(), any());
    }

    private PasswordLoginService service(boolean enabled) {
        return new PasswordLoginService(assessments, sessions, totp,
                new PasswordAvailabilityPolicy(enabled));
    }

    private PasswordLoginCommand command() {
        Digest32 digest = Digest32.fromBytes(new byte[32]);
        VerifiedDpopProof dpop = new VerifiedDpopProof(new RequestKeyThumbprint(digest),
                digest, now, "request-jwk");
        return new PasswordLoginCommand(new PasswordOperationContext(UUID.randomUUID(),
                "neo-mobile", "ANDROID", "installation-1234567890", "alice", "QkJCQkJCQkJCQkJCQkJCQg"),
                new PasswordVerification("alice", "secret"),
                new PasswordWireProofs(dpop, "request-proof", "device-proof", "response-jwk"),
                now, now.plusSeconds(8), now.plusSeconds(900));
    }

    private Fixture fixture(boolean primary) {
        UUID customerId = UUID.randomUUID();
        UUID generation = UUID.randomUUID();
        Digest32 digest = Digest32.fromBytes(new byte[32]);
        LoginDeviceSnapshot device = new LoginDeviceSnapshot(UUID.randomUUID(), customerId,
                "neo-mobile", "ANDROID", true, true, primary,
                now.plusSeconds(3600), 1, new StoredDeviceKey(new byte[]{1}, digest));
        VerifiedPasswordProofs proofs = new VerifiedPasswordProofs(new RequestKeyThumbprint(digest),
                digest, digest, new PasswordProofIds(digest, digest, digest), "request-jwk", "response-jwk");
        CustomerAuthenticationState customer = new CustomerAuthenticationState("customer-a",
                CustomerStatus.ELIGIBLE, 3, 0, now);
        return new Fixture(customerId, customer, device, proofs, generation);
    }

    private record Fixture(UUID customerId, CustomerAuthenticationState customer,
                           LoginDeviceSnapshot device, VerifiedPasswordProofs proofs,
                           UUID generation) { }
}
