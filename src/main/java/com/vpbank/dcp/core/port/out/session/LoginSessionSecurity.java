package com.vpbank.dcp.core.port.out.session;

import java.util.Objects;

/**
 * Current SQL security state needed before attempting to publish an ACTIVE session.
 *
 * <p>Components are grouped by the row they are read from so that no two neighbouring
 * components share a type: a wrong argument order cannot compile.
 */
public record LoginSessionSecurity(StoredCustomerSecurity customer,
                                   StoredDeviceSecurity device,
                                   SessionSecurityVersions versions,
                                   boolean biometricEnabled) {

    public LoginSessionSecurity {
        Objects.requireNonNull(customer, "customer");
        Objects.requireNonNull(device, "device");
        Objects.requireNonNull(versions, "versions");
    }
}
