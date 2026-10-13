package com.vpbank.dcp.infrastructure.persistence.projection;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public record CustomerOwnerView(UUID id, String customerId, String providerId,
                                String providerSubject, String status,
                                long statusVersion, long lastBlockVersion,
                                Instant checkedAt, long version) {
    public CustomerOwnerView {
        Objects.requireNonNull(id);
        Objects.requireNonNull(customerId);
        Objects.requireNonNull(status);
        Objects.requireNonNull(checkedAt);
    }
}
