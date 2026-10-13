package com.vpbank.dcp.infrastructure.adapter.out.redis.key;

import com.vpbank.dcp.core.port.out.session.SessionTokenLookup;
import java.util.Objects;

/** Single owner of the versioned restricted-login Redis key format. */
public final class PendingTotpKeys {
    public String forToken(SessionTokenLookup token) {
        Objects.requireNonNull(token);
        return "pending-totp:v1:" + token.version().value() + ":" + token.digest().base64Url();
    }
}
