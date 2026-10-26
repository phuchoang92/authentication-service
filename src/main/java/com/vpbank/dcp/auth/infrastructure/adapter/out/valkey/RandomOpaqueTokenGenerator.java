package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

import com.vpbank.dcp.auth.application.port.out.gateway.OpaqueTokenGenerator;
import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.model.OpaqueToken;
import com.vpbank.dcp.auth.domain.model.SessionId;
import java.security.SecureRandom;
import java.util.Base64;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/** {@code s1:auth:session:<channel>:<sessionId>:<base64url(32 random bytes)>}. */
@RequiredArgsConstructor
public final class RandomOpaqueTokenGenerator implements OpaqueTokenGenerator {
    private static final int SECRET_BYTES = 32;

    @NonNull private final SecureRandom secureRandom;

    @Override
    public OpaqueToken next(Channel channel, SessionId sessionId) {
        byte[] randomBytes = new byte[SECRET_BYTES];
        secureRandom.nextBytes(randomBytes);
        String secret = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
        return OpaqueToken.of(channel, sessionId, secret);
    }
}
