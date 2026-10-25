package com.vpbank.dcp.auth.adapter.out.valkey;

import com.vpbank.dcp.auth.application.port.out.SessionLookup;
import com.vpbank.dcp.auth.domain.model.OpaqueToken;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * The session key factory (RK02/RK03): {@code session:v1:<keyVersion>:<base64url HMAC-SHA256(key, token)>}
 * from DD 06/16. The token's {@code k<n>} prefix selects which HMAC key signs it, so keys can rotate
 * without rewriting stored sessions. No I/O, no clock, no TTL decisions here (RK10).
 */
public final class SessionKeys {
    static final String PREFIX = "session:v1:";
    private static final Pattern KEY_VERSION = Pattern.compile("k[1-9][0-9]{0,2}");
    private static final String ALGORITHM = "HmacSHA256";

    private final Map<String, byte[]> hmacKeysByVersion;

    /** One ≥32-byte HMAC key per token key version ({@code k1}, {@code k2}, …). */
    public SessionKeys(Map<String, byte[]> hmacKeysByVersion) {
        Objects.requireNonNull(hmacKeysByVersion, "hmacKeysByVersion");
        if (hmacKeysByVersion.isEmpty()) {
            throw new IllegalArgumentException("At least one session lookup key version is required");
        }
        hmacKeysByVersion.forEach((version, key) -> {
            if (!KEY_VERSION.matcher(version).matches() || key == null || key.length < 32) {
                throw new IllegalArgumentException("Session lookup key " + version + " must be k<n> with at least 32 bytes");
            }
        });
        this.hmacKeysByVersion = Map.copyOf(hmacKeysByVersion);
    }

    /** The lookup the token maps to; the BFF derives the same pair with the same key. */
    public SessionLookup lookupOf(OpaqueToken token) {
        return new SessionLookup(token.keyVersion(), digest(token));
    }

    public String forLookup(SessionLookup lookup) {
        return PREFIX + lookup.keyVersion() + ":" + lookup.digest();
    }

    /** Unpadded base64url of HMAC-SHA256 over the exact ASCII token (43 characters). */
    public String digest(OpaqueToken token) {
        byte[] key = hmacKeysByVersion.get(token.keyVersion());
        if (key == null) {
            throw new IllegalArgumentException("No session lookup key for version " + token.keyVersion());
        }
        try {
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(new SecretKeySpec(key, ALGORITHM));
            return Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(mac.doFinal(token.value().getBytes(StandardCharsets.US_ASCII)));
        } catch (GeneralSecurityException failure) {
            throw new IllegalStateException("HmacSHA256 is not available", failure);
        }
    }
}
