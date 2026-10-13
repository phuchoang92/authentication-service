package com.vpbank.dcp.infrastructure.persistence.codec;

import com.vpbank.dcp.core.domain.security.Digest32;
import java.util.Objects;

public record DeviceIdLookup(String keyId, Digest32 digest) {
    public DeviceIdLookup {
        Objects.requireNonNull(keyId);
        Objects.requireNonNull(digest);
    }

    @Override
    public String toString() {
        return "DeviceIdLookup[redacted]";
    }
}
