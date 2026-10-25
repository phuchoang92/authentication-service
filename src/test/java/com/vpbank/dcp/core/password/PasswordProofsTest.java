package com.vpbank.dcp.core.password;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.vpbank.dcp.core.security.Digest32;
import com.vpbank.dcp.core.security.RequestKeyThumbprint;
import com.vpbank.dcp.core.device.LoginDeviceRepository;
import com.vpbank.dcp.core.replay.ReplayAuthorityUnavailableException;
import com.vpbank.dcp.core.security.VerifiedDpopProof;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class PasswordProofsTest {
    private final LoginDeviceRepository devices = mock(LoginDeviceRepository.class);
    private final PasswordProofVerifier proofs = mock(PasswordProofVerifier.class);
    private final PasswordProofReplay replay = mock(PasswordProofReplay.class);
    private final PasswordProofs service = new PasswordProofs(devices, proofs, replay);
    private final Instant now = Instant.parse("2026-10-13T00:00:00Z");

    @Test
    void claimedBindingWithoutStoredKeyNeverReachesProofOrPasswordDispatch() {
        assertThat(service.admit(command("QkJCQkJCQkJCQkJCQkJCQg")))
                .isEqualTo(new PasswordProofAdmissionResult.Denied(LoginDenial.REJECTED));
        verify(proofs, never()).verify(any(), any());
        verify(replay, never()).reserve(any());
    }

    @Test
    void replayOfSameOperationIsRejectedBeforeCredentialVerification() {
        PasswordLoginCommand command = command(null);
        when(proofs.verify(any(PasswordProofRequest.class), eq(null))).thenReturn(verified());
        when(replay.reserve(any())).thenReturn(new PasswordReplayResult.Replayed());
        assertThat(service.admit(command))
                .isEqualTo(new PasswordProofAdmissionResult.Denied(LoginDenial.REJECTED));
    }

    @Test
    void validProofReservesOperationAndReturnsGeneration() {
        PasswordLoginCommand command = command(null);
        UUID generation = UUID.randomUUID();
        when(proofs.verify(any(PasswordProofRequest.class), eq(null))).thenReturn(verified());
        when(replay.reserve(any())).thenReturn(new PasswordReplayResult.Reserved(generation));
        assertThat(service.admit(command)).isEqualTo(new PasswordProofAdmissionResult.Admitted(
                new AdmittedProof(verified(), generation)));
    }

    /** A closed replay authority must never be answered with REJECTED: the App may retry later. */
    @Test
    void closedReplayAuthorityIsUnavailableAndNotRejected() {
        PasswordLoginCommand command = command(null);
        when(proofs.verify(any(PasswordProofRequest.class), eq(null))).thenReturn(verified());
        when(replay.reserve(any())).thenReturn(new PasswordReplayResult.AuthorityClosed());
        assertThat(service.admit(command))
                .isEqualTo(new PasswordProofAdmissionResult.Denied(LoginDenial.UNAVAILABLE));
    }

    @Test
    void unreachableReplayAuthorityIsUnavailableAndNotRejected() {
        PasswordLoginCommand command = command(null);
        when(proofs.verify(any(PasswordProofRequest.class), eq(null))).thenReturn(verified());
        when(replay.reserve(any())).thenThrow(new ReplayAuthorityUnavailableException(new RuntimeException("down")));
        assertThat(service.admit(command))
                .isEqualTo(new PasswordProofAdmissionResult.Denied(LoginDenial.UNAVAILABLE));
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
}
