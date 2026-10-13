package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.domain.customer.CustomerAuthenticationState;
import com.vpbank.dcp.core.port.out.device.LoginDeviceSnapshot;
import com.vpbank.dcp.core.port.out.password.VerifiedPasswordProofs;
import java.util.UUID;

/** Authenticated login route, not yet an ACTIVE or PENDING banking token. */
public sealed interface PasswordLoginAssessment {
    record LastTrusted(UUID customerId, CustomerAuthenticationState customer,
                       LoginDeviceSnapshot device, VerifiedPasswordProofs proofs,
                       UUID generation) implements PasswordLoginAssessment { }

    record OtherTrusted(UUID customerId, CustomerAuthenticationState customer,
                        LoginDeviceSnapshot device, VerifiedPasswordProofs proofs,
                        UUID generation) implements PasswordLoginAssessment { }

    record NewDevice(UUID customerId, CustomerAuthenticationState customer,
                     VerifiedPasswordProofs proofs, UUID generation)
            implements PasswordLoginAssessment { }

    record Rejected() implements PasswordLoginAssessment { }

    record Unavailable() implements PasswordLoginAssessment { }
}
