package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.domain.model.DeviceEnrollment;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/** SHA-256 digests the enrollment flows share: the MFA context binding and the challenge / token digests. */
final class EnrollmentDigests {
    private EnrollmentDigests() {
    }

    /** What MFA binds the transaction to (DD 20 §5): purpose, customer, channel, operation; recomputed, never stored. */
    static String contextDigest(DeviceEnrollment enrollment) {
        String context = enrollment.purpose().name()
                + ";" + enrollment.customerId().value()
                + ";" + enrollment.channel().name()
                + ";" + enrollment.id();
        return digest(context.getBytes(StandardCharsets.UTF_8));
    }

    static String digest(String text) {
        return digest(text.getBytes(StandardCharsets.US_ASCII));
    }

    static String digest(byte[] bytes) {
        try {
            byte[] sha256 = MessageDigest.getInstance("SHA-256").digest(bytes);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(sha256);
        } catch (NoSuchAlgorithmException failure) {
            throw new IllegalStateException("SHA-256 is not available", failure);
        }
    }

    /** Constant-time comparison of two digests in their text form. */
    static boolean sameDigest(String expected, String actual) {
        byte[] expectedBytes = expected.getBytes(StandardCharsets.US_ASCII);
        byte[] actualBytes = actual.getBytes(StandardCharsets.US_ASCII);
        return MessageDigest.isEqual(expectedBytes, actualBytes);
    }
}
