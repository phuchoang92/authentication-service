package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.port.in.password.PasswordLoginCommand;
import com.vpbank.dcp.core.port.out.device.LoginDeviceRepository;
import com.vpbank.dcp.core.port.out.device.LoginDeviceUnavailableException;
import com.vpbank.dcp.core.port.out.password.InvalidPasswordProofException;
import com.vpbank.dcp.core.port.out.password.PasswordProofReplay;
import com.vpbank.dcp.core.port.out.password.PasswordProofRequest;
import com.vpbank.dcp.core.port.out.password.PasswordProofVerifier;
import com.vpbank.dcp.core.port.out.password.PasswordReplayAttempt;
import com.vpbank.dcp.core.port.out.password.PasswordReplayResult;
import com.vpbank.dcp.core.port.out.password.StoredDeviceKey;
import com.vpbank.dcp.core.port.out.password.VerifiedPasswordProofs;
import com.vpbank.dcp.core.port.out.replay.ReplayAuthorityUnavailableException;
import java.util.Objects;

/** Verifies all App signatures and reserves replay markers before password dispatch. */
public final class AdmitPasswordProofService {
    private final LoginDeviceRepository devices;
    private final PasswordProofVerifier proofs;
    private final PasswordProofReplay replay;

    public AdmitPasswordProofService(LoginDeviceRepository devices,
                                     PasswordProofVerifier proofs,
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
                return new PasswordProofAdmissionResult.Unavailable();
            }
            if (deviceKey == null) {
                return new PasswordProofAdmissionResult.Rejected();
            }
        }
        VerifiedPasswordProofs verified;
        try {
            verified = proofs.verify(new PasswordProofRequest(command.operation(),
                    command.proofs(), command.now()), deviceKey);
        } catch (InvalidPasswordProofException failure) {
            return new PasswordProofAdmissionResult.Rejected();
        }
        PasswordReplayAttempt attempt = new PasswordReplayAttempt(command.operation().operationId(),
                verified.requestKey(), verified.deviceKeyThumbprint(), verified.proofIds());
        try {
            PasswordReplayResult reserved = replay.reserve(attempt);
            if (reserved instanceof PasswordReplayResult.Reserved admitted) {
                return new PasswordProofAdmissionResult.Admitted(verified, admitted.generation());
            }
            return reserved instanceof PasswordReplayResult.Replayed
                    ? new PasswordProofAdmissionResult.Rejected()
                    : new PasswordProofAdmissionResult.Unavailable();
        } catch (ReplayAuthorityUnavailableException failure) {
            return new PasswordProofAdmissionResult.Unavailable();
        }
    }
}
