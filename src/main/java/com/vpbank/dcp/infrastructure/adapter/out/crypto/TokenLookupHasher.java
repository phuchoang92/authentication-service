package com.vpbank.dcp.infrastructure.adapter.out.crypto;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.LookupKeyVersion;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Objects;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Derives a Redis lookup digest from the exact opaque token, never the token body alone. */
public final class TokenLookupHasher implements AutoCloseable {

    private final LookupKeyVersion keyVersion;
    private final byte[] secret;

    public TokenLookupHasher(LookupKeyVersion keyVersion, byte[] secret) {
        this.keyVersion = Objects.requireNonNull(keyVersion, "keyVersion");
        Objects.requireNonNull(secret, "secret");
        if (secret.length < 32) {
            throw new InvalidCryptographicInputException();
        }
        this.secret = secret.clone();
    }

    public Digest32 digest(String exactToken) {
        Objects.requireNonNull(exactToken, "exactToken");
        if (!exactToken.startsWith(keyVersion.value() + ".")
                || !exactToken.substring(keyVersion.value().length() + 1)
                        .matches("[A-Za-z0-9_-]{43}")) {
            throw new InvalidCryptographicInputException();
        }
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            return Digest32.fromBytes(mac.doFinal(exactToken.getBytes(StandardCharsets.US_ASCII)));
        } catch (GeneralSecurityException failure) {
            throw new CryptographicProviderUnavailableException(failure);
        }
    }

    @Override
    public void close() {
        Arrays.fill(secret, (byte) 0);
    }
}
