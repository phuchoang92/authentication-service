package com.vpbank.dcp.core.session;

import com.vpbank.dcp.core.customer.SubjectId;
import com.vpbank.dcp.core.customer.CustomerAuthenticationState;
import com.vpbank.dcp.core.device.LoginDeviceSnapshot;
import java.util.Objects;
import java.util.UUID;

/** Confirmed factors and current owner, not a token or session authority. */
public record SessionLoginEvidence(SubjectId subject, CustomerAuthenticationState customer,
                                   LoginDeviceSnapshot device, SessionKeyBindings keys,
                                   UUID generation, LoginConfirmation confirmation) {
    public SessionLoginEvidence {
        Objects.requireNonNull(subject);
        Objects.requireNonNull(customer);
        Objects.requireNonNull(device);
        Objects.requireNonNull(keys);
        Objects.requireNonNull(generation);
        Objects.requireNonNull(confirmation);
    }

    @Override
    public String toString() {
        return "SessionLoginEvidence[redacted]";
    }
}
