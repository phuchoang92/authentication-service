package com.vpbank.dcp.core.port.in.session;

import com.vpbank.dcp.core.domain.customer.SubjectId;
import com.vpbank.dcp.core.domain.customer.CustomerAuthenticationState;
import com.vpbank.dcp.core.port.out.device.LoginDeviceSnapshot;
import com.vpbank.dcp.core.port.out.session.SessionKeyBindings;
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
