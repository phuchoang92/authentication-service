package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.DevicePlatform;
import com.vpbank.dcp.auth.domain.enums.EnrollmentState;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import com.vpbank.dcp.auth.domain.model.EnrollmentTransaction;
import com.vpbank.dcp.auth.domain.model.SessionId;
import com.vpbank.dcp.auth.domain.model.TrustedDeviceId;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Enrollment transaction ↔ Valkey HASH fields (contract 16 style: every field a UTF-8 string, integers base-10,
 * {@code schemaVersion=1}). Decoding is strict: a missing or unknown field, or a value that does not parse,
 * means "no transaction", never a guessed default. {@code targetDeviceId} is present only for a known device,
 * {@code mfaTransactionId} only in MFA_REQUIRED. Ksrv's private key is stored as it is today in the restricted
 * session (slice 5 decision: not encrypted at rest yet).
 */
public final class EnrollmentTransactionHashCodec {
    static final String SCHEMA_VERSION = "1";
    static final String F_SCHEMA = "schemaVersion";
    static final String F_ENROLLMENT_ID = "enrollmentId";
    static final String F_CUSTOMER_ID = "customerId";
    static final String F_CHANNEL = "channel";
    static final String F_DEVICE_ID = "deviceId";
    static final String F_SESSION_ID = "sessionId";
    static final String F_STATE = "state";
    static final String F_TARGET_DEVICE_ID = "targetDeviceId";
    static final String F_DEVICE_JWK = "deviceJwk";
    static final String F_DEVICE_PLATFORM = "devicePlatform";
    static final String F_SERVER_PUBLIC_JWK = "serverPublicJwk";
    static final String F_SERVER_PRIVATE_JWK = "serverPrivateJwk";
    static final String F_CHALLENGE_DIGEST = "challengeDigest";
    static final String F_VERIFY_ATTEMPTS = "verifyAttempts";
    static final String F_MFA_TRANSACTION_ID = "mfaTransactionId";
    static final String F_EXPIRES_AT = "expiresAtMs";
    static final String F_VERSION = "version";
    private static final Set<String> REQUIRED = Set.of(F_SCHEMA, F_ENROLLMENT_ID, F_CUSTOMER_ID, F_CHANNEL, F_DEVICE_ID,
            F_SESSION_ID, F_STATE, F_DEVICE_JWK, F_DEVICE_PLATFORM, F_SERVER_PUBLIC_JWK, F_SERVER_PRIVATE_JWK,
            F_CHALLENGE_DIGEST, F_VERIFY_ATTEMPTS, F_EXPIRES_AT, F_VERSION);
    private static final Set<String> OPTIONAL = Set.of(F_TARGET_DEVICE_ID, F_MFA_TRANSACTION_ID);

    private EnrollmentTransactionHashCodec() {
    }

    public static Map<String, String> encode(EnrollmentTransaction transaction) {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put(F_SCHEMA, SCHEMA_VERSION);
        fields.put(F_ENROLLMENT_ID, transaction.id().value().toString());
        fields.put(F_CUSTOMER_ID, transaction.customerId().value());
        fields.put(F_CHANNEL, transaction.channel().name());
        fields.put(F_DEVICE_ID, transaction.deviceId().value());
        fields.put(F_SESSION_ID, transaction.sessionId().value().toString());
        fields.put(F_STATE, transaction.state().name());
        if (transaction.targetDeviceId() != null) {
            fields.put(F_TARGET_DEVICE_ID, transaction.targetDeviceId().value().toString());
        }
        fields.put(F_DEVICE_JWK, transaction.devicePublicJwk());
        fields.put(F_DEVICE_PLATFORM, transaction.platform().name());
        fields.put(F_SERVER_PUBLIC_JWK, transaction.serverPublicJwk());
        fields.put(F_SERVER_PRIVATE_JWK, transaction.serverPrivateJwk());
        fields.put(F_CHALLENGE_DIGEST, transaction.challengeDigest());
        fields.put(F_VERIFY_ATTEMPTS, Integer.toString(transaction.verifyAttempts()));
        if (transaction.mfaTransactionId() != null) {
            fields.put(F_MFA_TRANSACTION_ID, transaction.mfaTransactionId());
        }
        fields.put(F_EXPIRES_AT, Long.toString(transaction.expiresAt().toEpochMilli()));
        fields.put(F_VERSION, Long.toString(transaction.version()));
        return fields;
    }

    public static Optional<EnrollmentTransaction> decode(Map<String, String> fields) {
        if (fields == null) {
            return Optional.empty();
        }
        boolean hasEveryRequiredField = fields.keySet().containsAll(REQUIRED);
        boolean hasOnlyKnownFields = fields.keySet().stream()
                .allMatch(field -> REQUIRED.contains(field) || OPTIONAL.contains(field));
        boolean isCurrentSchema = SCHEMA_VERSION.equals(fields.get(F_SCHEMA));
        if (!hasEveryRequiredField || !hasOnlyKnownFields || !isCurrentSchema) {
            return Optional.empty();
        }

        try {
            String targetDeviceId = fields.get(F_TARGET_DEVICE_ID);
            EnrollmentTransaction transaction = EnrollmentTransaction.builder()
                    .id(new EnrollmentId(UUID.fromString(fields.get(F_ENROLLMENT_ID))))
                    .customerId(new CustomerId(fields.get(F_CUSTOMER_ID)))
                    .channel(Channel.valueOf(fields.get(F_CHANNEL)))
                    .deviceId(new DeviceId(fields.get(F_DEVICE_ID)))
                    .sessionId(new SessionId(UUID.fromString(fields.get(F_SESSION_ID))))
                    .state(EnrollmentState.valueOf(fields.get(F_STATE)))
                    .targetDeviceId(targetDeviceId == null ? null : new TrustedDeviceId(UUID.fromString(targetDeviceId)))
                    .devicePublicJwk(fields.get(F_DEVICE_JWK))
                    .platform(DevicePlatform.valueOf(fields.get(F_DEVICE_PLATFORM)))
                    .serverPublicJwk(fields.get(F_SERVER_PUBLIC_JWK))
                    .serverPrivateJwk(fields.get(F_SERVER_PRIVATE_JWK))
                    .challengeDigest(fields.get(F_CHALLENGE_DIGEST))
                    .verifyAttempts(Integer.parseInt(fields.get(F_VERIFY_ATTEMPTS)))
                    .mfaTransactionId(fields.get(F_MFA_TRANSACTION_ID))
                    .expiresAt(instant(fields.get(F_EXPIRES_AT)))
                    .version(Long.parseLong(fields.get(F_VERSION)))
                    .build();
            return Optional.of(transaction);
        } catch (IllegalArgumentException malformed) {
            // NumberFormatException is one too; the record's invariants (state, MFA ID, negatives) land here as well.
            return Optional.empty();
        }
    }

    private static Instant instant(String millis) {
        long value = Long.parseLong(millis);
        if (value < 0) {
            throw new IllegalArgumentException("Negative timestamp");
        }
        return Instant.ofEpochMilli(value);
    }
}
