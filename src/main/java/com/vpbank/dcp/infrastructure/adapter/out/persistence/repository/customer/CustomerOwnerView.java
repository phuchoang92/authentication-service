package com.vpbank.dcp.infrastructure.adapter.out.persistence.repository.customer;

import com.vpbank.dcp.core.domain.customer.CustomerAuthenticationState;
import java.util.Objects;
import java.util.UUID;

public record CustomerOwnerView(UUID id, CustomerAuthenticationState customer) {
    public CustomerOwnerView {
        Objects.requireNonNull(id);
        Objects.requireNonNull(customer);
    }

    @Override
    public String toString() { return "CustomerOwnerView[redacted]"; }
}
