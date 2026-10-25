package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

import com.vpbank.dcp.auth.application.port.out.gateway.OpaqueTokenGenerator;
import com.vpbank.dcp.auth.domain.model.OpaqueToken;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

import java.security.SecureRandom;
import java.util.Base64;

/** {@code k<version>.<base64url(32 random bytes)>} for the current lookup key version. */
@RequiredArgsConstructor
public final class RandomOpaqueTokenGenerator implements OpaqueTokenGenerator {
    @NonNull private final SecureRandom random;
    @NonNull private final String keyVersion;

    @Override
    public OpaqueToken next() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return new OpaqueToken(keyVersion + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes));
    }
}
