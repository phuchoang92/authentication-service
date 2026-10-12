package com.vpbank.dcp.infrastructure.adapter.out.persistence.repository.password;

import java.util.Objects;

public record VerifiedPasswordIdentityView(String issuer, String subject) {
    public VerifiedPasswordIdentityView {
        Objects.requireNonNull(issuer);
        Objects.requireNonNull(subject);
    }

    @Override
    public String toString() { return "VerifiedPasswordIdentityView[redacted]"; }
}
