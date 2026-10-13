package com.vpbank.dcp.core.port.out.session;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.LookupKeyVersion;
import java.util.Objects;

/** A token lookup digest paired with the key version that produced it. */
public record SessionTokenLookup(LookupKeyVersion version, Digest32 digest) {
    public SessionTokenLookup {
        Objects.requireNonNull(version);
        Objects.requireNonNull(digest);
    }

    @Override
    public String toString() {
        return "SessionTokenLookup[redacted]";
    }
}
