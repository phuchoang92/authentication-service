package com.vpbank.dcp.core.application.trusteddevice;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.vpbank.dcp.core.domain.customer.CustomerAuthenticationState;
import com.vpbank.dcp.core.domain.customer.CustomerNumber;
import com.vpbank.dcp.core.domain.customer.CustomerStatus;
import com.vpbank.dcp.core.domain.customer.SubjectId;
import com.vpbank.dcp.core.domain.device.BindingId;
import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.port.in.session.IssueLoginSessionUseCase;
import com.vpbank.dcp.core.port.in.session.LoginConfirmation;
import com.vpbank.dcp.core.port.in.session.SessionLoginEvidence;
import com.vpbank.dcp.core.port.in.session.SessionLoginResult;
import com.vpbank.dcp.core.port.in.trusteddevice.ConfirmTrustedDeviceResult;
import com.vpbank.dcp.core.port.out.customer.CustomerDirectory;
import com.vpbank.dcp.core.port.out.device.LoginDeviceRepository;
import com.vpbank.dcp.core.port.out.device.LoginDeviceSnapshot;
import com.vpbank.dcp.core.port.out.password.StoredDeviceKey;
import com.vpbank.dcp.core.port.out.session.PreparedSession;
import com.vpbank.dcp.core.port.out.trusteddevice.KeyExchange;
import com.vpbank.dcp.core.port.out.trusteddevice.LoginKeys;
import com.vpbank.dcp.core.port.out.trusteddevice.RestrictedSessionStep;
import com.vpbank.dcp.core.port.out.trusteddevice.StoredRestrictedSession;
import com.vpbank.dcp.core.port.out.trusteddevice.TrustTarget;
import com.vpbank.dcp.core.port.out.trusteddevice.WrappedServerKey;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

class TrustedSessionIssuerTest {
    private static final Instant NOW = Instant.parse("2026-10-18T00:00:00Z");
    private final CustomerDirectory customers = mock(CustomerDirectory.class);
    private final LoginDeviceRepository devices = mock(LoginDeviceRepository.class);
    private final IssueLoginSessionUseCase sessions = mock(IssueLoginSessionUseCase.class);
    private final TrustedSessionIssuer issuer = new TrustedSessionIssuer(customers, devices, sessions);
    private final Digest32 digest = Digest32.fromBytes(new byte[32]);
    private final SubjectId owner = new SubjectId(UUID.randomUUID());
    private final BindingId binding = new BindingId(UUID.randomUUID());
    private final StoredRestrictedSession trust = new StoredRestrictedSession(UUID.randomUUID(),
            UUID.randomUUID(), owner, new CustomerNumber("CUST-1"), 3, "neo-mobile",
            new TrustTarget.NewDevice(), digest, new LoginKeys("request-jwk", digest, "response-jwk"),
            "ANDROID", UUID.randomUUID(), NOW.plusSeconds(600), RestrictedSessionStep.MFA, 0,
            new KeyExchange(new WrappedServerKey("w1", new byte[] {1}), "s", digest, "d", digest),
            "mfa-transaction-0000000000001");

    @Test
    void issuesAnMfaConfirmedSessionBoundToTheLoginKeys() {
        customer(3, CustomerStatus.ELIGIBLE);
        device(true, true, true);
        PreparedSession prepared = mock(PreparedSession.class);
        ArgumentCaptor<SessionLoginEvidence> evidence = ArgumentCaptor.forClass(SessionLoginEvidence.class);
        when(sessions.issue(eq(trust.operationId()), eq(NOW), evidence.capture()))
                .thenReturn(new SessionLoginResult.Active(prepared));

        assertThat(issuer.issue(trust, binding, "device-id-1234567890", NOW))
                .isEqualTo(new ConfirmTrustedDeviceResult.Active(prepared));
        assertThat(evidence.getValue().confirmation()).isEqualTo(LoginConfirmation.MFA_CONFIRMED);
        assertThat(evidence.getValue().keys().requestPublicJwk()).isEqualTo("request-jwk");
        assertThat(evidence.getValue().keys().responsePublicJwk()).isEqualTo("response-jwk");
    }

    /** A Customer change since login needs a fresh login, never a session on stale state. */
    @Test
    void changedOrBlockedCustomerIsRejected() {
        device(true, true, true);
        customer(4, CustomerStatus.ELIGIBLE);
        assertThat(issuer.issue(trust, binding, "device-id-1234567890", NOW))
                .isInstanceOf(ConfirmTrustedDeviceResult.Rejected.class);
        customer(3, CustomerStatus.BLOCKED);
        assertThat(issuer.issue(trust, binding, "device-id-1234567890", NOW))
                .isInstanceOf(ConfirmTrustedDeviceResult.Rejected.class);
        verify(sessions, never()).issue(any(), any(), any());
    }

    @Test
    void deviceThatIsNotTheMatchingActivePrimaryIsRejected() {
        customer(3, CustomerStatus.ELIGIBLE);
        device(false, true, true);
        assertThat(issuer.issue(trust, binding, "device-id-1234567890", NOW))
                .isInstanceOf(ConfirmTrustedDeviceResult.Rejected.class);
        device(true, true, false);
        assertThat(issuer.issue(trust, binding, "device-id-1234567890", NOW))
                .isInstanceOf(ConfirmTrustedDeviceResult.Rejected.class);
        verify(sessions, never()).issue(any(), any(), any());
    }

    private void customer(long statusVersion, CustomerStatus status) {
        when(customers.currentStatus(new CustomerNumber("CUST-1"))).thenReturn(
                new CustomerAuthenticationState(new CustomerNumber("CUST-1"), status, statusVersion,
                        status.allowsLogin() ? 0 : statusVersion, NOW));
    }

    private void device(boolean matches, boolean active, boolean primary) {
        when(devices.currentByBinding(owner, "neo-mobile", "device-id-1234567890", binding))
                .thenReturn(Optional.of(new LoginDeviceSnapshot(binding, owner, "neo-mobile",
                        "ANDROID", matches, active, primary, NOW.plusSeconds(3600), 1,
                        new StoredDeviceKey(new byte[] {1}, digest))));
    }
}
