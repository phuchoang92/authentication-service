package com.vpbank.dcp.core.security;

import java.util.Objects;

public record RequestKeyThumbprint(Digest32 digest) {

    public RequestKeyThumbprint {
        Objects.requireNonNull(digest, "digest");
    }
}
