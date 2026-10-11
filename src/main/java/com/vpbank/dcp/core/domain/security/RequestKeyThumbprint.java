package com.vpbank.dcp.core.domain.security;

import java.util.Objects;

public record RequestKeyThumbprint(Digest32 digest) {

    public RequestKeyThumbprint {
        Objects.requireNonNull(digest, "digest");
    }
}
