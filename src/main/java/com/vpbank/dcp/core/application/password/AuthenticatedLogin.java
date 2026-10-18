package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.domain.customer.SubjectId;
import com.vpbank.dcp.core.domain.customer.CustomerAuthenticationState;
import com.vpbank.dcp.core.port.out.device.LoginDeviceSnapshot;
import java.util.Objects;

/**
 * Everything settled before the login's final action: the proof is admitted, the owner is
 * accepted and the device is resolved. No two components share a type, so a wrong argument
 * order cannot compile.
 */
public record AuthenticatedLogin(SubjectId subject, CustomerAuthenticationState customer,
                                 LoginDeviceSnapshot device, AdmittedProof proof) {
    public AuthenticatedLogin {
        Objects.requireNonNull(subject, "subject");
        Objects.requireNonNull(customer, "customer");
        Objects.requireNonNull(device, "device");
        Objects.requireNonNull(proof, "proof");
    }
}
