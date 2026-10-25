package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

import com.vpbank.dcp.auth.application.port.out.gateway.OpaqueTokenGenerator;
import com.vpbank.dcp.auth.domain.model.OpaqueToken;
import java.security.SecureRandom;
import java.util.Base64;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/** {@code k<version>.<base64url(32 random bytes)>} for the current lookup key version. */
@RequiredArgsConstructor
public final class RandomOpaqueTokenGenerator implements OpaqueTokenGenerator {
    @NonNull private final SecureRandom secureRandom;
    @NonNull private final String keyVersion;

    @Override
    public OpaqueToken next() {
        byte[] randomBytes = new byte[32];
        secureRandom.nextBytes(randomBytes);
        String randomPart = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
        return new OpaqueToken(keyVersion + "." + randomPart);
    }
}
