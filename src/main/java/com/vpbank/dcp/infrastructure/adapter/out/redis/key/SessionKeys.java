package com.vpbank.dcp.infrastructure.adapter.out.redis.key;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.LookupKeyVersion;
import java.util.Objects;

public final class SessionKeys {

    public String forLookup(LookupKeyVersion version, Digest32 lookupDigest) {
        Objects.requireNonNull(version, "version");
        Objects.requireNonNull(lookupDigest, "lookupDigest");
        return "session:v1:" + version.value() + ":" + lookupDigest.base64Url();
    }
}
