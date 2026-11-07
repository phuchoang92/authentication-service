package com.vpbank.dcp.auth.application.port.out.model;

import com.vpbank.dcp.auth.domain.model.Session;
import lombok.NonNull;

/**
 * A session as read from the store: the lookup it was found under and the digest of the token's secret the store
 * keeps with it. Both are needed to write it back; the digest is never the secret.
 */
public record StoredSession(@NonNull SessionLookup lookup, @NonNull Session session, @NonNull String secretDigest) {
}
