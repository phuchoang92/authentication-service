package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.port.in.password.PasswordLoginCommand;
import com.vpbank.dcp.core.port.out.password.VerifiedPasswordProofs;
import java.util.Objects;
import java.util.UUID;

/** Orders proof admission, one password attempt, Customer check and current device routing. */
public final class AssessPasswordLoginService {
    private final AdmitPasswordProofService proofs;
    private final VerifyPasswordIdentityService identities;
    private final ResolvePasswordDeviceService devices;

    public AssessPasswordLoginService(AdmitPasswordProofService proofs,
                                      VerifyPasswordIdentityService identities,
                                      ResolvePasswordDeviceService devices) {
        this.proofs = Objects.requireNonNull(proofs);
        this.identities = Objects.requireNonNull(identities);
        this.devices = Objects.requireNonNull(devices);
    }

    public PasswordLoginAssessment assess(PasswordLoginCommand command) {
        Objects.requireNonNull(command);
        PasswordProofAdmissionResult admitted = proofs.admit(command);
        if (admitted instanceof PasswordProofAdmissionResult.Rejected) {
            return new PasswordLoginAssessment.Rejected();
        }
        if (admitted instanceof PasswordProofAdmissionResult.Unavailable) {
            return new PasswordLoginAssessment.Unavailable();
        }
        PasswordProofAdmissionResult.Admitted proof = (PasswordProofAdmissionResult.Admitted) admitted;
        PasswordIdentityResult identity = identities.verify(command);
        if (identity instanceof PasswordIdentityResult.Rejected) {
            return new PasswordLoginAssessment.Rejected();
        }
        if (identity instanceof PasswordIdentityResult.Unavailable) {
            return new PasswordLoginAssessment.Unavailable();
        }
        PasswordIdentityResult.Verified verified = (PasswordIdentityResult.Verified) identity;
        PasswordDeviceRouteResult route = devices.resolve(verified.customerId(), command, proof.proofs());
        return toAssessment(verified, proof.proofs(), proof.generation(), route);
    }

    private PasswordLoginAssessment toAssessment(PasswordIdentityResult.Verified identity,
                                                  VerifiedPasswordProofs proofs, UUID generation,
                                                  PasswordDeviceRouteResult route) {
        if (route instanceof PasswordDeviceRouteResult.LastTrusted last) {
            return new PasswordLoginAssessment.LastTrusted(identity.customerId(), identity.customer(),
                    last.device(), proofs, generation);
        }
        if (route instanceof PasswordDeviceRouteResult.OtherTrusted other) {
            return new PasswordLoginAssessment.OtherTrusted(identity.customerId(), identity.customer(),
                    other.device(), proofs, generation);
        }
        if (route instanceof PasswordDeviceRouteResult.NewDevice) {
            return new PasswordLoginAssessment.NewDevice(identity.customerId(), identity.customer(),
                    proofs, generation);
        }
        return route instanceof PasswordDeviceRouteResult.Unavailable
                ? new PasswordLoginAssessment.Unavailable()
                : new PasswordLoginAssessment.Rejected();
    }
}
