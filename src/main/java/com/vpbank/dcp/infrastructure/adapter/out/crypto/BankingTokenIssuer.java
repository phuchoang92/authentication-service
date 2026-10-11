package com.vpbank.dcp.infrastructure.adapter.out.crypto;

import com.vpbank.dcp.core.domain.security.LookupKeyVersion;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;

/** Generates a fresh 256-bit native token; Redis lookup uses HMAC of its exact ASCII bytes. */
public final class BankingTokenIssuer {

    private final LookupKeyVersion version;
    private final SecureRandom random;

    public BankingTokenIssuer(LookupKeyVersion version, SecureRandom random) {
        this.version = Objects.requireNonNull(version, "version");
        this.random = Objects.requireNonNull(random, "random");
    }

    public OpaqueBankingToken issue() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return new OpaqueBankingToken(version.value() + "."
                + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes));
    }
}
