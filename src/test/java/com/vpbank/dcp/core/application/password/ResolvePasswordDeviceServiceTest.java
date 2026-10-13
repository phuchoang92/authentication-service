package com.vpbank.dcp.core.application.password;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.vpbank.dcp.core.domain.device.TrustedDeviceRouting;
import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.RequestKeyThumbprint;
import com.vpbank.dcp.core.port.in.password.PasswordLoginCommand;
import com.vpbank.dcp.core.port.out.device.LoginDeviceRepository;
import com.vpbank.dcp.core.port.out.device.LoginDeviceSnapshot;
import com.vpbank.dcp.core.port.out.keycloak.PasswordVerification;
import com.vpbank.dcp.core.port.out.password.PasswordOperationContext;
import com.vpbank.dcp.core.port.out.password.PasswordProofIds;
import com.vpbank.dcp.core.port.out.password.PasswordWireProofs;
import com.vpbank.dcp.core.port.out.password.StoredDeviceKey;
import com.vpbank.dcp.core.port.out.password.VerifiedPasswordProofs;
import com.vpbank.dcp.core.port.out.security.VerifiedDpopProof;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class ResolvePasswordDeviceServiceTest {
    private static final String BINDING_ID = "QkJCQkJCQkJCQkJCQkJCQg";
    private final UUID customerId = UUID.randomUUID();
    private final UUID bindingId = UUID.randomUUID();
    private final Instant now = Instant.parse("2026-10-13T00:00:00Z");
    private final Digest32 digest = Digest32.fromBytes(new byte[32]);
    private final LoginDeviceRepository devices = mock(LoginDeviceRepository.class);
    private final ResolvePasswordDeviceService service = new ResolvePasswordDeviceService(
            devices, new TrustedDeviceRouting());

    @Test
    void absentBindingIsNewDevice() {
        assertThat(service.resolve(customerId, command(null), proofs(false)))
                .isInstanceOf(PasswordDeviceRouteResult.NewDevice.class);
    }

    @Test
    void primaryDeviceRequiresCurrentOwnerInstallationAndPossession() {
        when(devices.current(customerId, "neo-mobile", "installation-1234567890", BINDING_ID))
                .thenReturn(Optional.of(snapshot(true, true)));
        assertThat(service.resolve(customerId, command(BINDING_ID), proofs(true)))
                .isInstanceOf(PasswordDeviceRouteResult.LastTrusted.class);
        assertThat(service.resolve(customerId, command(BINDING_ID), proofs(false)))
                .isInstanceOf(PasswordDeviceRouteResult.Rejected.class);
    }

    @Test
    void nonPrimaryDeviceNeedsTotpRatherThanDirectActive() {
        when(devices.current(customerId, "neo-mobile", "installation-1234567890", BINDING_ID))
                .thenReturn(Optional.of(snapshot(false, true)));
        assertThat(service.resolve(customerId, command(BINDING_ID), proofs(true)))
                .isInstanceOf(PasswordDeviceRouteResult.OtherTrusted.class);
    }

    @Test
    void wrongInstallationNeverDowngradesToNewDevice() {
        when(devices.current(customerId, "neo-mobile", "installation-1234567890", BINDING_ID))
                .thenReturn(Optional.of(snapshot(true, false)));
        assertThat(service.resolve(customerId, command(BINDING_ID), proofs(true)))
                .isInstanceOf(PasswordDeviceRouteResult.Rejected.class);
    }

    private LoginDeviceSnapshot snapshot(boolean primary, boolean installationMatches) {
        return new LoginDeviceSnapshot(bindingId, customerId, "neo-mobile", "ANDROID",
                installationMatches, true, primary, now.plusSeconds(60), 1,
                new StoredDeviceKey(new byte[] {1}, digest));
    }

    private PasswordLoginCommand command(String publicBindingId) {
        VerifiedDpopProof dpop = new VerifiedDpopProof(new RequestKeyThumbprint(digest),
                digest, now, "public-jwk");
        return new PasswordLoginCommand(new PasswordOperationContext(UUID.randomUUID(),
                "neo-mobile", "ANDROID", "installation-1234567890", "alice", publicBindingId),
                new PasswordVerification("alice", "secret"),
                new PasswordWireProofs(dpop, "request-proof", "device-proof", "recipient-key"),
                now, now.plusSeconds(8), now.plusSeconds(900));
    }

    private VerifiedPasswordProofs proofs(boolean deviceProof) {
        return new VerifiedPasswordProofs(new RequestKeyThumbprint(digest), digest,
                deviceProof ? digest : null,
                new PasswordProofIds(digest, digest, deviceProof ? digest : null),
                "public-jwk", "recipient-key");
    }
}
