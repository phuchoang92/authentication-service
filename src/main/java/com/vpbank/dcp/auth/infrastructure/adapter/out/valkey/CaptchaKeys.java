package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

import com.vpbank.dcp.auth.domain.model.CaptchaAnswer;
import com.vpbank.dcp.auth.domain.model.CaptchaId;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.Objects;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Key factory for CAPTCHA challenges: {@code captcha:v1:<uuid>}; answers are stored as a keyed HMAC, never in clear. */
public final class CaptchaKeys {
    static final String PREFIX = "captcha:v1:";
    private static final String ALGORITHM = "HmacSHA256";
    private final byte[] hmacKey;

    public CaptchaKeys(byte[] hmacKey) {
        Objects.requireNonNull(hmacKey, "hmacKey");
        if (hmacKey.length < 32) {
            throw new IllegalArgumentException("CAPTCHA HMAC key must be at least 32 bytes");
        }
        this.hmacKey = hmacKey.clone();
    }

    public String forChallenge(CaptchaId id) {
        return PREFIX + id.value();
    }

    /** HMAC over the normalized (upper-case) answer, so a Valkey copy does not reveal answers. */
    public String answerDigest(CaptchaAnswer answer) {
        try {
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(new SecretKeySpec(hmacKey, ALGORITHM));
            return Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(mac.doFinal(answer.normalized().getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException failure) {
            throw new IllegalStateException("HmacSHA256 is not available", failure);
        }
    }
}
