package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

import com.vpbank.dcp.auth.domain.model.CaptchaAnswer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import lombok.NonNull;

/**
 * The keyed digest a CAPTCHA answer is stored as: HMAC-SHA256 over the normalized (upper-case) answer under the
 * configured key, so a copy of the store does not reveal answers.
 */
public final class CaptchaAnswerDigest {
    private static final String ALGORITHM = "HmacSHA256";
    private final byte[] hmacKey;

    public CaptchaAnswerDigest(@NonNull byte[] hmacKey) {
        if (hmacKey.length < 32) {
            throw new IllegalArgumentException("CAPTCHA HMAC key must be at least 32 bytes");
        }
        this.hmacKey = hmacKey.clone();
    }

    public String of(CaptchaAnswer answer) {
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
