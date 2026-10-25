package com.vpbank.dcp.core.password;

import com.vpbank.dcp.core.device.LoginDeviceRepository;
import com.vpbank.dcp.core.device.LoginDeviceUnavailableException;
import com.vpbank.dcp.core.device.StoredDeviceKey;
import com.vpbank.dcp.core.replay.ReplayAuthorityUnavailableException;
import java.util.Objects;
import java.util.UUID;

/** Verifies all App signatures and reserves replay markers before password dispatch. */
public final class PasswordProofs {
    private final LoginDeviceRepository devices;
    private final PasswordProofVerifier proofs;
    private final PasswordProofReplay replay;

    public PasswordProofs(LoginDeviceRepository devices, PasswordProofVerifier proofs,
                          PasswordProofReplay replay) {
        this.devices = Objects.requireNonNull(devices);
        this.proofs = Objects.requireNonNull(proofs);
        this.replay = Objects.requireNonNull(replay);
    }

    public PasswordProofAdmissionResult admit(PasswordLoginCommand command) {
        Objects.requireNonNull(command);
        StoredDeviceKey deviceKey = null;
        if (command.operation().claimedBindingId() != null) {
            try {
                deviceKey = devices.keyForProof(command.operation().claimedBindingId()).orElse(null);
            } catch (LoginDeviceUnavailableException failure) {
                return new PasswordProofAdmissionResult.Denied(LoginDenial.UNAVAILABLE);
            }
            if (deviceKey == null) {
                return new PasswordProofAdmissionResult.Denied(LoginDenial.REJECTED);
            }
        }
        VerifiedPasswordProofs verified;
        try {
            verified = proofs.verify(new PasswordProofRequest(command.operation(),
                    command.proofs(), command.now()), deviceKey);
        } catch (InvalidPasswordProofException failure) {
            return new PasswordProofAdmissionResult.Denied(LoginDenial.REJECTED);
        }
        PasswordReplayAttempt attempt = new PasswordReplayAttempt(command.operation().operationId(),
                verified.requestKey(), verified.deviceKeyThumbprint(), verified.proofIds());
        PasswordReplayResult reserved;
        try {
            reserved = replay.reserve(attempt);
        } catch (ReplayAuthorityUnavailableException failure) {
            return new PasswordProofAdmissionResult.Denied(LoginDenial.UNAVAILABLE);
        }
        return switch (reserved) {
            case PasswordReplayResult.Reserved(UUID generation) ->
                    new PasswordProofAdmissionResult.Admitted(
                            new AdmittedProof(verified, generation));
            case PasswordReplayResult.Replayed() ->
                    new PasswordProofAdmissionResult.Denied(LoginDenial.REJECTED);
            case PasswordReplayResult.AuthorityClosed() ->
                    new PasswordProofAdmissionResult.Denied(LoginDenial.UNAVAILABLE);
        };
    }
}
