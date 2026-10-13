package com.vpbank.dcp.infrastructure.adapter.out.totp;

import com.vpbank.dcp.core.domain.totp.TotpCode;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** RFC 6238 SHA-1 profile retained for interoperability with the existing 30-second codes. */
public final class TotpAlgorithm {
    private static final int STEP_SECONDS = 30;
    // One adjacent step in either direction accommodates bounded device clock drift.
    private static final int WINDOW_STEPS = 1;
    private static final int CODE_MODULUS = 1_000_000;

    public long matchingStep(byte[] secret, TotpCode submitted, Instant now) {
        if (secret == null || secret.length != 20) {
            throw new InvalidTotpSecretException();
        }
        char[] digits = submitted.copyDigits();
        try {
            long currentStep = Math.floorDiv(now.getEpochSecond(), STEP_SECONDS);
            long matchedStep = -1;
            for (long step = currentStep - WINDOW_STEPS; step <= currentStep + WINDOW_STEPS; step++) {
                if (step < 0) {
                    continue;
                }
                char[] expected = codeForStep(secret, step);
                boolean matches = constantTimeEquals(expected, digits);
                Arrays.fill(expected, '\0');
                if (matches) {
                    // The six-digit output can collide within the acceptance window.
                    // An ambiguous code is rejected rather than consuming the wrong step.
                    if (matchedStep != -1) {
                        return -1;
                    }
                    matchedStep = step;
                }
            }
            return matchedStep;
        } finally {
            Arrays.fill(digits, '\0');
        }
    }

    char[] codeForStep(byte[] secret, long step) {
        if (secret == null || secret.length != 20 || step < 0) {
            throw new InvalidTotpSecretException();
        }
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(secret, "HmacSHA1"));
            byte[] digest = mac.doFinal(ByteBuffer.allocate(Long.BYTES).putLong(step).array());
            int offset = digest[digest.length - 1] & 0x0f;
            int truncated = ((digest[offset] & 0x7f) << 24)
                    | ((digest[offset + 1] & 0xff) << 16)
                    | ((digest[offset + 2] & 0xff) << 8)
                    | (digest[offset + 3] & 0xff);
            int value = truncated % CODE_MODULUS;
            char[] result = new char[6];
            for (int position = result.length - 1; position >= 0; position--) {
                result[position] = (char) ('0' + value % 10);
                value /= 10;
            }
            Arrays.fill(digest, (byte) 0);
            return result;
        } catch (java.security.GeneralSecurityException failure) {
            throw new InvalidTotpSecretException(failure);
        }
    }

    private static boolean constantTimeEquals(char[] left, char[] right) {
        int difference = left.length ^ right.length;
        for (int index = 0; index < left.length; index++) {
            difference |= left[index] ^ right[index];
        }
        return difference == 0;
    }
}
