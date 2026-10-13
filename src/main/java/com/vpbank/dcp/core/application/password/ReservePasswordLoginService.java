package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.port.in.password.PasswordLoginCommand;
import com.vpbank.dcp.core.port.out.password.*;

import java.security.MessageDigest;
import java.util.Objects;

/**
 * Reserves all one-shot proofs and durable command identity before provider dispatch.
 */
public final class ReservePasswordLoginService {

    private final PasswordDeviceKeyRepository deviceKeys;
    private final PasswordProofVerifier proofVerifier;
    private final PasswordProofReplay proofReplay;
    private final PasswordCommandHasher commandHasher;
    private final PasswordOperationRepository operations;

    public ReservePasswordLoginService(PasswordDeviceKeyRepository deviceKeys,
                                       PasswordProofVerifier proofVerifier,
                                       PasswordProofReplay proofReplay,
                                       PasswordCommandHasher commandHasher,
                                       PasswordOperationRepository operations) {
        this.deviceKeys = Objects.requireNonNull(deviceKeys, "deviceKeys");
        this.proofVerifier = Objects.requireNonNull(proofVerifier, "proofVerifier");
        this.proofReplay = Objects.requireNonNull(proofReplay, "proofReplay");
        this.commandHasher = Objects.requireNonNull(commandHasher, "commandHasher");
        this.operations = Objects.requireNonNull(operations, "operations");
    }

    public PasswordLoginReservationResult reserve(PasswordLoginCommand command) {
        Objects.requireNonNull(command, "command");
        StoredDeviceKey deviceKey = null;
        if (command.operation().claimedBindingId() != null) {
            deviceKey = deviceKeys.findActive(command.operation()).orElse(null);
            if (deviceKey == null) {
                return new PasswordLoginReservationResult.Rejected();
            }
        }
        var request = new PasswordProofRequest(command.operation(), command.proofs(), command.now());
        VerifiedPasswordProofs verified;
        try {
            verified = proofVerifier.verify(request, deviceKey);
        } catch (InvalidPasswordProofException invalid) {
            return new PasswordLoginReservationResult.Rejected();
        }
        var replay = proofReplay.reserve(new PasswordReplayAttempt(verified.requestKey(),
                verified.deviceKeyThumbprint(), verified.proofIds()));
        if (replay instanceof PasswordReplayResult.Replayed) {
            return new PasswordLoginReservationResult.Rejected();
        }
        if (replay instanceof PasswordReplayResult.AuthorityClosed) {
            return new PasswordLoginReservationResult.AuthorityClosed();
        }
        var semantic = new PasswordSemanticCommand(command.operation(), command.credential(), verified);
        var fingerprints = commandHasher.prepare(semantic);
        var reservation = new PasswordReservation(command.operation(), verified, fingerprints,
                command.now(), command.credentialDeadline(), command.journeyDeadline());
        return result(command, semantic, operations.reserve(reservation));
    }

    private PasswordLoginReservationResult result(PasswordLoginCommand command,
                                                  PasswordSemanticCommand semantic,
                                                  PasswordReservationResult reservation) {
        if (reservation instanceof PasswordReservationResult.Created(java.util.UUID journeyId)) {
            return new PasswordLoginReservationResult.Reserved(command.operation().operationId(),
                    journeyId);
        }
        if (reservation instanceof PasswordReservationResult.Existing(
                java.util.UUID operationId, java.util.UUID journeyId,
                com.vpbank.dcp.core.domain.security.Digest32 commandDigest, String commandKeyId
        )) {
            boolean sameOperation = command.operation().operationId().equals(operationId);
            boolean sameCommand = MessageDigest.isEqual(commandDigest.bytes(),
                    commandHasher.digest(semantic, commandKeyId).bytes());
            if (sameOperation && sameCommand) {
                return new PasswordLoginReservationResult.Existing(operationId,
                        journeyId);
            }
        }
        return new PasswordLoginReservationResult.Conflict();
    }
}
