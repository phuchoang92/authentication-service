package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.domain.device.BindingId;
import com.vpbank.dcp.core.domain.customer.SubjectId;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.vpbank.dcp.core.domain.device.DeviceTrustPolicy;
import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.RequestKeyThumbprint;
import com.vpbank.dcp.core.port.in.password.PasswordLoginCommand;
import com.vpbank.dcp.core.port.out.device.LoginDeviceRepository;
import com.vpbank.dcp.core.port.out.device.LoginDeviceSnapshot;
import com.vpbank.dcp.core.port.out.device.LoginDeviceUnavailableException;
import com.vpbank.dcp.core.port.out.credential.PasswordVerification;
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

class LoginDevicesTest {
    private static final String BINDING_ID = "QkJCQkJCQkJCQkJCQkJCQg";
    private final SubjectId subject = new SubjectId(UUID.randomUUID());
    private final BindingId bindingId = new BindingId(UUID.randomUUID());
    private final Instant now = Instant.parse("2026-10-13T00:00:00Z");
    private final Digest32 digest = Digest32.fromBytes(new byte[32]);
    private final LoginDeviceRepository devices = mock(LoginDeviceRepository.class);
    private final LoginDevices service = new LoginDevices(devices, new DeviceTrustPolicy());

    @Test
    void absentBindingIsNewDevice() {
        assertThat(service.decide(subject, command(null), proofs(false)))
                .isInstanceOf(DeviceTrustResult.NewDevice.class);
    }

    @Test
    void primaryDeviceRequiresCurrentOwnerInstallationAndPossession() {
        when(devices.current(subject, "neo-mobile", "installation-1234567890", BINDING_ID))
                .thenReturn(Optional.of(snapshot(true, true)));
        assertThat(service.decide(subject, command(BINDING_ID), proofs(true)))
                .isInstanceOf(DeviceTrustResult.LastTrusted.class);
        assertThat(service.decide(subject, command(BINDING_ID), proofs(false)))
                .isEqualTo(new DeviceTrustResult.Denied(LoginDenial.REJECTED));
    }

    @Test
    void nonPrimaryDeviceNeedsTotpRatherThanDirectActive() {
        when(devices.current(subject, "neo-mobile", "installation-1234567890", BINDING_ID))
                .thenReturn(Optional.of(snapshot(false, true)));
        assertThat(service.decide(subject, command(BINDING_ID), proofs(true)))
                .isInstanceOf(DeviceTrustResult.OtherTrusted.class);
    }

    @Test
    void wrongInstallationNeverDowngradesToNewDevice() {
        when(devices.current(subject, "neo-mobile", "installation-1234567890", BINDING_ID))
                .thenReturn(Optional.of(snapshot(true, false)));
        assertThat(service.decide(subject, command(BINDING_ID), proofs(true)))
                .isEqualTo(new DeviceTrustResult.Denied(LoginDenial.REJECTED));
    }

    /** A supplied but unknown binding is REJECTED, never the NEW_DEVICE enrolment path. */
    @Test
    void unknownBindingIsRejectedAndNeverNewDevice() {
        when(devices.current(subject, "neo-mobile", "installation-1234567890", BINDING_ID))
                .thenReturn(Optional.empty());
        assertThat(service.decide(subject, command(BINDING_ID), proofs(true)))
                .isEqualTo(new DeviceTrustResult.Denied(LoginDenial.REJECTED));
    }

    /** A storage outage must not be reported as a rejected device. */
    @Test
    void unreachableDeviceStoreIsUnavailableAndNotRejected() {
        when(devices.current(subject, "neo-mobile", "installation-1234567890", BINDING_ID))
                .thenThrow(new LoginDeviceUnavailableException(new RuntimeException("down")));
        assertThat(service.decide(subject, command(BINDING_ID), proofs(true)))
                .isEqualTo(new DeviceTrustResult.Denied(LoginDenial.UNAVAILABLE));
    }

    private LoginDeviceSnapshot snapshot(boolean primary, boolean installationMatches) {
        return new LoginDeviceSnapshot(bindingId, subject, "neo-mobile", "ANDROID",
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
