package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.port.out.password.*;

import java.security.MessageDigest;
import java.util.Objects;

/**
 * Reserves all one-shot proofs and durable command identity before provider dispatch.
 */
public final class PasswordAdmissionService {

    private final PasswordDeviceKeyStore deviceKeys;
    private final PasswordProofVerifier proofVerifier;
    private final PasswordProofReplay proofReplay;
    private final PasswordCommandHasher commandHasher;
    private final PasswordOperationStore operations;

    public PasswordAdmissionService(PasswordDeviceKeyStore deviceKeys,
                                    PasswordProofVerifier proofVerifier,
                                    PasswordProofReplay proofReplay,
                                    PasswordCommandHasher commandHasher,
                                    PasswordOperationStore operations) {
        this.deviceKeys = Objects.requireNonNull(deviceKeys, "deviceKeys");
        this.proofVerifier = Objects.requireNonNull(proofVerifier, "proofVerifier");
        this.proofReplay = Objects.requireNonNull(proofReplay, "proofReplay");
        this.commandHasher = Objects.requireNonNull(commandHasher, "commandHasher");
        this.operations = Objects.requireNonNull(operations, "operations");
    }

    public PasswordAdmissionResult reserve(PasswordAdmissionCommand command) {
        Objects.requireNonNull(command, "command");
        StoredDeviceKey deviceKey = null;
        if (command.operation().claimedBindingId() != null) {
            deviceKey = deviceKeys.findActive(command.operation()).orElse(null);
            if (deviceKey == null) {
                return new PasswordAdmissionResult.Rejected();
            }
        }
        var request = new PasswordProofRequest(command.operation(), command.proofs(), command.now());
        VerifiedPasswordProofs verified;
        try {
            verified = proofVerifier.verify(request, deviceKey);
        } catch (InvalidPasswordProofException invalid) {
            return new PasswordAdmissionResult.Rejected();
        }
        var replay = proofReplay.reserve(new PasswordReplayAttempt(verified.requestKey(),
                verified.deviceKeyThumbprint(), verified.proofIds()));
        if (replay instanceof PasswordReplayResult.Replayed) {
            return new PasswordAdmissionResult.Rejected();
        }
        if (replay instanceof PasswordReplayResult.AuthorityClosed) {
            return new PasswordAdmissionResult.AuthorityClosed();
        }
        var semantic = new PasswordSemanticCommand(command.operation(), command.credential(), verified);
        var fingerprints = commandHasher.prepare(semantic);
        var reservation = new PasswordReservation(command.operation(), verified, fingerprints,
                command.now(), command.credentialDeadline(), command.journeyDeadline());
        return result(command, semantic, operations.reserve(reservation));
    }

    private PasswordAdmissionResult result(PasswordAdmissionCommand command,
                                           PasswordSemanticCommand semantic,
                                           PasswordReservationResult reservation) {
        if (reservation instanceof PasswordReservationResult.Created created) {
            return new PasswordAdmissionResult.Reserved(command.operation().operationId(),
                    created.journeyId());
        }
        if (reservation instanceof PasswordReservationResult.Existing existing) {
            boolean sameOperation = command.operation().operationId().equals(existing.operationId());
            boolean sameCommand = MessageDigest.isEqual(existing.commandDigest().bytes(),
                    commandHasher.digest(semantic, existing.commandKeyId()).bytes());
            if (sameOperation && sameCommand) {
                return new PasswordAdmissionResult.Existing(existing.operationId(),
                        existing.journeyId());
            }
        }
        return new PasswordAdmissionResult.Conflict();
    }
}
