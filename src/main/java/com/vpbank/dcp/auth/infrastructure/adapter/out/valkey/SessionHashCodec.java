package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.DevicePlatform;
import com.vpbank.dcp.auth.domain.enums.SessionStatus;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.EnrollmentContext;
import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import com.vpbank.dcp.auth.domain.model.Session;
import com.vpbank.dcp.auth.domain.model.SessionId;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Session ↔ Valkey HASH fields (contract 16 style: every field a UTF-8 string, integers as
 * base-10 ms, booleans absent here, {@code schemaVersion=1}). Decoding is strict: a missing or
 * unknown field, or a value that does not parse, means "no session" — never a guessed default.
 * No token, password or key material is ever stored.
 */
public final class SessionHashCodec {
    static final String SCHEMA_VERSION = "1";
    static final String F_SCHEMA = "schemaVersion";
    static final String F_SESSION_ID = "sessionId";
    static final String F_CUSTOMER_ID = "customerId";
    static final String F_DEVICE_ID = "deviceId";
    static final String F_CHANNEL = "channel";
    static final String F_STATUS = "status";
    static final String F_CREATED_AT = "createdAtMs";
    static final String F_IDLE_EXPIRES_AT = "idleExpiresAtMs";
    static final String F_ABSOLUTE_EXPIRES_AT = "absoluteExpiresAtMs";
    static final String F_SESSION_VERSION = "sessionVersion";
    /**
     * Enrollment context of a restricted session (DD 20 §4): all present or all absent. Ksrv's private key lives only here.
     */
    static final String F_ENROLLMENT_ID = "enrollmentId";
    static final String F_DEVICE_JWK = "deviceJwk";
    static final String F_DEVICE_PLATFORM = "devicePlatform";
    static final String F_SERVER_PUBLIC_JWK = "serverPublicJwk";
    static final String F_SERVER_PRIVATE_JWK = "serverPrivateJwk";
    static final String F_CHALLENGE_DIGEST = "challengeDigest";
    static final String F_KEY_PROVEN = "keyProven";
    private static final Set<String> REQUIRED = Set.of(F_SCHEMA, F_SESSION_ID, F_CUSTOMER_ID, F_CHANNEL, F_STATUS,
            F_CREATED_AT, F_IDLE_EXPIRES_AT, F_ABSOLUTE_EXPIRES_AT, F_SESSION_VERSION);
    private static final Set<String> ENROLLMENT = Set.of(F_ENROLLMENT_ID, F_DEVICE_JWK, F_DEVICE_PLATFORM, F_SERVER_PUBLIC_JWK,
            F_SERVER_PRIVATE_JWK, F_CHALLENGE_DIGEST, F_KEY_PROVEN);
    private static final Set<String> KNOWN = Set.of(F_SCHEMA, F_SESSION_ID, F_CUSTOMER_ID, F_DEVICE_ID, F_CHANNEL,
            F_STATUS, F_CREATED_AT, F_IDLE_EXPIRES_AT, F_ABSOLUTE_EXPIRES_AT, F_SESSION_VERSION, F_ENROLLMENT_ID, F_DEVICE_JWK,
            F_DEVICE_PLATFORM, F_SERVER_PUBLIC_JWK, F_SERVER_PRIVATE_JWK, F_CHALLENGE_DIGEST, F_KEY_PROVEN);

    private SessionHashCodec() {
    }

    public static Map<String, String> encode(Session session) {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put(F_SCHEMA, SCHEMA_VERSION);
        fields.put(F_SESSION_ID, session.id().value().toString());
        fields.put(F_CUSTOMER_ID, session.customerId().value());
        if (session.deviceId() != null) {
            fields.put(F_DEVICE_ID, session.deviceId().value());
        }
        fields.put(F_CHANNEL, session.channel().name());
        fields.put(F_STATUS, session.status().name());
        fields.put(F_CREATED_AT, millis(session.createdAt()));
        fields.put(F_IDLE_EXPIRES_AT, millis(session.idleExpiresAt()));
        fields.put(F_ABSOLUTE_EXPIRES_AT, millis(session.absoluteExpiresAt()));
        fields.put(F_SESSION_VERSION, Long.toString(session.sessionVersion()));
        if (session.enrollment() != null) {
            EnrollmentContext enrollmentContext = session.enrollment();
            fields.put(F_ENROLLMENT_ID, enrollmentContext.enrollmentId().value().toString());
            fields.put(F_DEVICE_JWK, enrollmentContext.devicePublicJwk());
            fields.put(F_DEVICE_PLATFORM, enrollmentContext.platform().name());
            fields.put(F_SERVER_PUBLIC_JWK, enrollmentContext.serverPublicJwk());
            fields.put(F_SERVER_PRIVATE_JWK, enrollmentContext.serverPrivateJwk());
            fields.put(F_CHALLENGE_DIGEST, enrollmentContext.challengeDigest());
            fields.put(F_KEY_PROVEN, flag(enrollmentContext.keyProven()));
        }
        return fields;
    }

    public static Optional<Session> decode(Map<String, String> fields) {
        if (fields == null) {
            return Optional.empty();
        }
        boolean hasEveryRequiredField = fields.keySet().containsAll(REQUIRED);
        boolean hasOnlyKnownFields = KNOWN.containsAll(fields.keySet());
        boolean isCurrentSchema = SCHEMA_VERSION.equals(fields.get(F_SCHEMA));
        if (!hasEveryRequiredField || !hasOnlyKnownFields || !isCurrentSchema) {
            return Optional.empty();
        }

        boolean hasAnyEnrollmentField = fields.keySet().stream().anyMatch(ENROLLMENT::contains);
        boolean hasEveryEnrollmentField = fields.keySet().containsAll(ENROLLMENT);
        if (hasAnyEnrollmentField && !hasEveryEnrollmentField) {
            return Optional.empty();
        }

        try {
            String deviceId = fields.get(F_DEVICE_ID);

            EnrollmentContext enrollmentContext = null;
            if (hasAnyEnrollmentField) {
                enrollmentContext = EnrollmentContext.builder()
                        .enrollmentId(new EnrollmentId(UUID.fromString(fields.get(F_ENROLLMENT_ID))))
                        .devicePublicJwk(fields.get(F_DEVICE_JWK))
                        .platform(DevicePlatform.valueOf(fields.get(F_DEVICE_PLATFORM)))
                        .serverPublicJwk(fields.get(F_SERVER_PUBLIC_JWK))
                        .serverPrivateJwk(fields.get(F_SERVER_PRIVATE_JWK))
                        .challengeDigest(fields.get(F_CHALLENGE_DIGEST))
                        .keyProven(flag(fields.get(F_KEY_PROVEN)))
                        .build();
            }

            Session session = Session.builder()
                    .enrollment(enrollmentContext)
                    .id(new SessionId(UUID.fromString(fields.get(F_SESSION_ID))))
                    .customerId(new CustomerId(fields.get(F_CUSTOMER_ID)))
                    .deviceId(deviceId == null ? null : new DeviceId(deviceId))
                    .channel(Channel.valueOf(fields.get(F_CHANNEL)))
                    .status(SessionStatus.valueOf(fields.get(F_STATUS)))
                    .createdAt(instant(fields.get(F_CREATED_AT)))
                    .idleExpiresAt(instant(fields.get(F_IDLE_EXPIRES_AT)))
                    .absoluteExpiresAt(instant(fields.get(F_ABSOLUTE_EXPIRES_AT)))
                    .sessionVersion(Long.parseLong(fields.get(F_SESSION_VERSION)))
                    .build();
            return Optional.of(session);
        } catch (IllegalArgumentException malformed) {
            return Optional.empty();
        }
    }

    private static String flag(boolean value) {
        return value ? "1" : "0";
    }

    private static boolean flag(String value) {
        if ("1".equals(value)) {
            return true;
        }
        if ("0".equals(value)) {
            return false;
        }
        throw new IllegalArgumentException("Flag must be 0 or 1");
    }

    static String millis(Instant instant) {
        return Long.toString(instant.toEpochMilli());
    }

    private static Instant instant(String millis) {
        long value = Long.parseLong(millis);
        if (value < 0) {
            throw new IllegalArgumentException("Negative timestamp");
        }
        return Instant.ofEpochMilli(value);
    }
}
