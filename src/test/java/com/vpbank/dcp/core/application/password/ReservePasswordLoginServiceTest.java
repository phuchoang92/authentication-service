package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.port.in.password.PasswordLoginCommand;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.RequestKeyThumbprint;
import com.vpbank.dcp.core.port.out.keycloak.PasswordVerification;
import com.vpbank.dcp.core.port.out.password.PasswordCommandHasher;
import com.vpbank.dcp.core.port.out.password.PasswordDeviceKeyRepository;
import com.vpbank.dcp.core.port.out.password.PasswordOperationContext;
import com.vpbank.dcp.core.port.out.password.PasswordOperationRepository;
import com.vpbank.dcp.core.port.out.password.PasswordProofIds;
import com.vpbank.dcp.core.port.out.password.PasswordProofReplay;
import com.vpbank.dcp.core.port.out.password.PasswordProofRequest;
import com.vpbank.dcp.core.port.out.password.PasswordProofVerifier;
import com.vpbank.dcp.core.port.out.password.PasswordReplayAttempt;
import com.vpbank.dcp.core.port.out.password.PasswordReplayResult;
import com.vpbank.dcp.core.port.out.password.PasswordReservation;
import com.vpbank.dcp.core.port.out.password.PasswordReservationFingerprints;
import com.vpbank.dcp.core.port.out.password.PasswordReservationResult;
import com.vpbank.dcp.core.port.out.password.PasswordSemanticCommand;
import com.vpbank.dcp.core.port.out.password.PasswordWireProofs;
import com.vpbank.dcp.core.port.out.password.VerifiedPasswordProofs;
import java.net.URI;
import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ReservePasswordLoginServiceTest {

    private final PasswordDeviceKeyRepository keys = mock(PasswordDeviceKeyRepository.class);
    private final PasswordProofVerifier verifier = mock(PasswordProofVerifier.class);
    private final PasswordProofReplay replay = mock(PasswordProofReplay.class);
    private final PasswordCommandHasher hasher = mock(PasswordCommandHasher.class);
    private final PasswordOperationRepository operations = mock(PasswordOperationRepository.class);
    private final ReservePasswordLoginService service = new ReservePasswordLoginService(keys,
            verifier, replay, hasher, operations);

    private PasswordLoginCommand command;
    private VerifiedPasswordProofs verified;
    private PasswordReservationFingerprints fingerprints;

    @BeforeEach
    void arrange() {
        var operation = new PasswordOperationContext(UUID.randomUUID(), "neo-mobile", "ANDROID",
                "install-1", "alice", null);
        Instant now = Instant.now();
        command = new PasswordLoginCommand(operation,
                new PasswordVerification("alice", "secret-test-only"),
                new PasswordWireProofs(URI.create("https://api.bank.test/api/v1/authentications/password"),
                        "dpop", "requestProof", null, "{}"), now,
                now.plusSeconds(120), now.plusSeconds(300));
        verified = new VerifiedPasswordProofs(new RequestKeyThumbprint(digest(1)), digest(2),
                null, new PasswordProofIds(digest(3), digest(4), null), "{}", "{}");
        fingerprints = new PasswordReservationFingerprints(digest(5), digest(6), digest(7),
                "h1", digest(8));
        when(verifier.verify(any(PasswordProofRequest.class),
                org.mockito.ArgumentMatchers.isNull())).thenReturn(verified);
        when(replay.reserve(any(PasswordReplayAttempt.class)))
                .thenReturn(new PasswordReplayResult.Reserved(UUID.randomUUID()));
        when(hasher.prepare(any(PasswordSemanticCommand.class))).thenReturn(fingerprints);
    }

    @Test
    void reservesBeforeAnyProviderDispatch() {
        UUID journey = UUID.randomUUID();
        when(operations.reserve(any(PasswordReservation.class)))
                .thenReturn(new PasswordReservationResult.Created(journey));
        assertThat(service.reserve(command)).isEqualTo(new PasswordLoginReservationResult.Reserved(
                command.operation().operationId(), journey));
        verify(replay).reserve(any(PasswordReplayAttempt.class));
        verify(operations).reserve(any(PasswordReservation.class));
    }

    @Test
    void replayNeverReservesSql() {
        when(replay.reserve(any(PasswordReplayAttempt.class)))
                .thenReturn(new PasswordReplayResult.Replayed());
        assertThat(service.reserve(command)).isInstanceOf(PasswordLoginReservationResult.Rejected.class);
        verify(operations, never()).reserve(any());
    }

    @Test
    void closedAuthorityNeverReservesSql() {
        when(replay.reserve(any(PasswordReplayAttempt.class)))
                .thenReturn(new PasswordReplayResult.AuthorityClosed());
        assertThat(service.reserve(command))
                .isInstanceOf(PasswordLoginReservationResult.AuthorityClosed.class);
        verify(operations, never()).reserve(any());
    }

    @Test
    void sqlFailureDoesNotBecomeAnAuthenticationSuccess() {
        when(operations.reserve(any(PasswordReservation.class)))
                .thenThrow(new IllegalStateException("test-only database failure"));
        assertThatThrownBy(() -> service.reserve(command))
                .isInstanceOf(IllegalStateException.class);
        verify(replay).reserve(any(PasswordReplayAttempt.class));
    }

    @Test
    void duplicateWithDifferentPasswordDigestConflicts() {
        UUID journey = UUID.randomUUID();
        when(operations.reserve(any(PasswordReservation.class)))
                .thenReturn(new PasswordReservationResult.Existing(
                        command.operation().operationId(), journey, digest(9), "h1"));
        when(hasher.digest(any(PasswordSemanticCommand.class),
                org.mockito.ArgumentMatchers.eq("h1"))).thenReturn(digest(7));
        assertThat(service.reserve(command)).isInstanceOf(PasswordLoginReservationResult.Conflict.class);
    }

    @Test
    void sameCommandUnderRetainedKeyRecoversOriginalJourney() {
        UUID journey = UUID.randomUUID();
        when(operations.reserve(any(PasswordReservation.class)))
                .thenReturn(new PasswordReservationResult.Existing(
                        command.operation().operationId(), journey, digest(9), "old-key"));
        when(hasher.digest(any(PasswordSemanticCommand.class),
                org.mockito.ArgumentMatchers.eq("old-key"))).thenReturn(digest(9));
        assertThat(service.reserve(command)).isEqualTo(new PasswordLoginReservationResult.Existing(
                command.operation().operationId(), journey));
    }

    @Test
    void missingClaimedDeviceKeyNeverChecksCredential() {
        var operation = new PasswordOperationContext(command.operation().operationId(),
                "neo-mobile", "ANDROID", "install-1", "alice", UUID.randomUUID());
        var withBinding = new PasswordLoginCommand(operation, command.credential(),
                command.proofs(), command.now(), command.credentialDeadline(),
                command.journeyDeadline());
        when(keys.findActive(operation)).thenReturn(Optional.empty());
        assertThat(service.reserve(withBinding)).isInstanceOf(PasswordLoginReservationResult.Rejected.class);
        verify(verifier, never()).verify(any(), any());
    }

    private Digest32 digest(int fill) {
        byte[] bytes = new byte[32];
        Arrays.fill(bytes, (byte) fill);
        return Digest32.fromBytes(bytes);
    }
}
