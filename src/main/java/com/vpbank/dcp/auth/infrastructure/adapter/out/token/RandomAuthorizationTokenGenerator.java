package com.vpbank.dcp.auth.infrastructure.adapter.out.token;

import com.vpbank.dcp.auth.application.port.out.gateway.AuthorizationTokenGenerator;
import java.security.SecureRandom;
import java.util.Base64;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/** 32 random bytes as unpadded base64url: the one-time QR token the primary device hands to a new device. */
@RequiredArgsConstructor
public final class RandomAuthorizationTokenGenerator implements AuthorizationTokenGenerator {
    private static final int TOKEN_BYTES = 32;

    @NonNull private final SecureRandom secureRandom;

    @Override
    public String next() {
        byte[] randomBytes = new byte[TOKEN_BYTES];
        secureRandom.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }
}
