package com.vpbank.dcp.core.session;

import com.vpbank.dcp.core.customer.CustomerNumber;
import com.vpbank.dcp.core.customer.SubjectId;
import java.util.Objects;

/** The customer a restricted login was for, and the status version it saw. */
public record PinnedCustomer(SubjectId owner, CustomerNumber number, long statusVersion) {
    public PinnedCustomer {
        Objects.requireNonNull(owner, "owner");
        Objects.requireNonNull(number, "number");
        if (statusVersion < 0) {
            throw new IllegalArgumentException("Invalid restricted session value");
        }
    }
}
