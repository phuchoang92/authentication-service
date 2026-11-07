package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.regex.Pattern;
import lombok.NonNull;

/**
 * What the session record keeps of the token's secret (draft 21 §2, decided 2026-11-07):
 * {@code base64url(SHA-256(secret))}, 43 characters, no padding. The secret has 256 random bits, so an unkeyed
 * hash is enough; whoever reads a dump of the store cannot rebuild a token. Auth and the BFF compute the same
 * digest from the token the app presents.
 */
public final class SessionSecretDigest {
    private static final Pattern FORMAT = Pattern.compile("[A-Za-z0-9_-]{43}");

    private SessionSecretDigest() {
    }

    public static String of(@NonNull String secret) {
        byte[] digest = sha256().digest(secret.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    /** Constant-time; a stored value that is not a digest never matches. */
    public static boolean matches(String storedDigest, @NonNull String presentedSecret) {
        if (storedDigest == null || !isDigest(storedDigest)) {
            return false;
        }
        byte[] stored = storedDigest.getBytes(StandardCharsets.US_ASCII);
        byte[] presented = of(presentedSecret).getBytes(StandardCharsets.US_ASCII);
        return MessageDigest.isEqual(stored, presented);
    }

    public static boolean isDigest(@NonNull String value) {
        return FORMAT.matcher(value).matches();
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException missing) {
            throw new IllegalStateException("SHA-256 is part of every Java runtime", missing);
        }
    }
}
