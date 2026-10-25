package com.vpbank.dcp.core.session;

import java.time.Instant;
import java.util.Objects;

/** Customer status ordering and the fixed freshness deadline supplied by source policy. */
public record CustomerStatusFreshness(long customerStatusVersion, Instant validUntil) {
    public CustomerStatusFreshness {
        Objects.requireNonNull(validUntil, "validUntil");
    }
}
