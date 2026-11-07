package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

import com.vpbank.dcp.auth.domain.model.Session;
import lombok.NonNull;

/** What one session record holds: the session, and the digest of the token's secret that opens it. */
public record SessionRecord(@NonNull Session session, @NonNull String secretDigest) {
    public SessionRecord {
        if (!SessionSecretDigest.isDigest(secretDigest)) {
            throw new IllegalArgumentException("A secret digest is 43 base64url characters");
        }
    }
}
