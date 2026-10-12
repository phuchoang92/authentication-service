package com.vpbank.dcp.infrastructure.persistence.projection;

import java.util.Objects;

/** Immutable database values; domain restoration belongs to the persistence mapper. */
public record ConfirmedPasswordOwnerView(
        String issuer,
        String providerSubject,
        CustomerOwnerView customer) {
    public ConfirmedPasswordOwnerView {
        Objects.requireNonNull(issuer, "issuer");
        Objects.requireNonNull(providerSubject, "providerSubject");
        Objects.requireNonNull(customer, "customer");
    }

    @Override
    public String toString() {
        return "ConfirmedPasswordOwnerView[redacted]";
    }
}
