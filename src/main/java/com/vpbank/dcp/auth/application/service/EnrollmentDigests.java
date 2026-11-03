package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.EnrollmentPurpose;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceEnrollment;
import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import com.vpbank.dcp.auth.domain.model.EnrollmentTransaction;
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
        return contextDigest(enrollment.purpose(), enrollment.customerId(), enrollment.channel(), enrollment.id());
    }

    /** The same binding for a primary enrollment still in the cache (slice 11): it gives the same digest as its row. */
    static String contextDigest(EnrollmentTransaction transaction) {
        return contextDigest(EnrollmentPurpose.TRUST_DEVICE, transaction.customerId(), transaction.channel(), transaction.id());
    }

    private static String contextDigest(EnrollmentPurpose purpose, CustomerId customerId, Channel channel,
                                        EnrollmentId enrollmentId) {
        String context = purpose.name()
                + ";" + customerId.value()
                + ";" + channel.name()
                + ";" + enrollmentId;
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
