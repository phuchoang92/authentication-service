package com.vpbank.dcp.core.application.password;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.vpbank.dcp.core.domain.customer.CustomerAuthenticationState;
import com.vpbank.dcp.core.domain.customer.CustomerStatus;
import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.RequestKeyThumbprint;
import com.vpbank.dcp.core.port.in.password.PasswordLoginCommand;
import com.vpbank.dcp.core.port.out.device.LoginDeviceSnapshot;
import com.vpbank.dcp.core.port.out.keycloak.PasswordVerification;
import com.vpbank.dcp.core.port.out.password.PasswordOperationContext;
import com.vpbank.dcp.core.port.out.password.PasswordProofIds;
import com.vpbank.dcp.core.port.out.password.PasswordWireProofs;
import com.vpbank.dcp.core.port.out.password.StoredDeviceKey;
import com.vpbank.dcp.core.port.out.password.VerifiedPasswordProofs;
import com.vpbank.dcp.core.port.out.security.VerifiedDpopProof;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class AssessPasswordLoginServiceTest {
    private final AdmitPasswordProofService proofs = mock(AdmitPasswordProofService.class);
    private final VerifyPasswordIdentityService identities = mock(VerifyPasswordIdentityService.class);
    private final ResolvePasswordDeviceService devices = mock(ResolvePasswordDeviceService.class);
    private final AssessPasswordLoginService service = new AssessPasswordLoginService(proofs, identities, devices);
    private final Instant now = Instant.parse("2026-10-13T00:00:00Z");

    @Test
    void invalidProofDoesNotDispatchPassword() {
        PasswordLoginCommand command = command(null);
        when(proofs.admit(command)).thenReturn(new PasswordProofAdmissionResult.Rejected());

        assertThat(service.assess(command)).isInstanceOf(PasswordLoginAssessment.Rejected.class);
        verify(identities, never()).verify(any());
    }

    @Test
    void passwordTimeoutCannotRouteOrIssueSession() {
        PasswordLoginCommand command = command(null);
        when(proofs.admit(command)).thenReturn(new PasswordProofAdmissionResult.Admitted(verified(), UUID.randomUUID()));
        when(identities.verify(command)).thenReturn(new PasswordIdentityResult.Unavailable());

        assertThat(service.assess(command)).isInstanceOf(PasswordLoginAssessment.Unavailable.class);
        verify(devices, never()).resolve(any(), any(), any());
    }

    @Test
    void primaryTrustedDeviceIsEligibleForSessionIssuance() {
        String bindingId = "QkJCQkJCQkJCQkJCQkJCQg";
        PasswordLoginCommand command = command(bindingId);
        UUID customerId = UUID.randomUUID();
        UUID generation = UUID.randomUUID();
        CustomerAuthenticationState customer = customer();
        LoginDeviceSnapshot device = device(customerId);
        when(proofs.admit(command)).thenReturn(new PasswordProofAdmissionResult.Admitted(verified(), generation));
        when(identities.verify(command)).thenReturn(new PasswordIdentityResult.Verified(customerId, customer));
        when(devices.resolve(customerId, command, verified()))
                .thenReturn(new PasswordDeviceRouteResult.LastTrusted(device));

        assertThat(service.assess(command)).isEqualTo(new PasswordLoginAssessment.LastTrusted(
                customerId, customer, device, verified(), generation));
    }

    @Test
    void missingBindingRequiresNewDeviceMfaNotAnActiveSession() {
        PasswordLoginCommand command = command(null);
        UUID customerId = UUID.randomUUID();
        UUID generation = UUID.randomUUID();
        when(proofs.admit(command)).thenReturn(new PasswordProofAdmissionResult.Admitted(verified(), generation));
        when(identities.verify(command)).thenReturn(new PasswordIdentityResult.Verified(customerId, customer()));
        when(devices.resolve(customerId, command, verified())).thenReturn(new PasswordDeviceRouteResult.NewDevice());

        assertThat(service.assess(command)).isInstanceOf(PasswordLoginAssessment.NewDevice.class);
    }

    private PasswordLoginCommand command(String bindingId) {
        Digest32 digest = Digest32.fromBytes(new byte[32]);
        VerifiedDpopProof dpop = new VerifiedDpopProof(new RequestKeyThumbprint(digest),
                digest, now, "public-jwk");
        return new PasswordLoginCommand(new PasswordOperationContext(UUID.randomUUID(),
                "neo-mobile", "ANDROID", "installation-1234567890", "alice", bindingId),
                new PasswordVerification("alice", "secret"),
                new PasswordWireProofs(dpop, "request-proof", bindingId == null ? null : "device-proof",
                        "recipient-key"), now, now.plusSeconds(8), now.plusSeconds(900));
    }

    private VerifiedPasswordProofs verified() {
        Digest32 digest = Digest32.fromBytes(new byte[32]);
        return new VerifiedPasswordProofs(new RequestKeyThumbprint(digest), digest, null,
                new PasswordProofIds(digest, digest, null), "public-jwk", "recipient-key");
    }

    private CustomerAuthenticationState customer() {
        return new CustomerAuthenticationState("customer-a", CustomerStatus.ELIGIBLE, 3, 0, now);
    }

    private LoginDeviceSnapshot device(UUID customerId) {
        Digest32 digest = Digest32.fromBytes(new byte[32]);
        return new LoginDeviceSnapshot(UUID.randomUUID(), customerId, "neo-mobile", "ANDROID",
                true, true, true, now.plusSeconds(3600), 1, new StoredDeviceKey(new byte[]{1}, digest));
    }
}
