package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.SessionStatus;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.DeviceSigningKey;
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
 * No token, password or private key material is ever stored; a restricted session carries the public signing
 * key the device proved at login (slice 13), both of its fields or neither.
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
    /** The token's secret, written by the adapter at create and compared on every read by token (slice 7). */
    static final String F_SECRET = "secret";
    static final String F_DEVICE_KEY_JWK = "deviceKeyJwk";
    static final String F_DEVICE_KEY_JKT = "deviceKeyJkt";
    private static final Set<String> REQUIRED = Set.of(F_SCHEMA, F_SESSION_ID, F_CUSTOMER_ID, F_CHANNEL, F_STATUS,
            F_CREATED_AT, F_IDLE_EXPIRES_AT, F_ABSOLUTE_EXPIRES_AT, F_SESSION_VERSION);
    /** The enrollment context of slice 5 left the session for its own cache record in slice 11. */
    private static final Set<String> KNOWN = Set.of(F_SCHEMA, F_SESSION_ID, F_CUSTOMER_ID, F_DEVICE_ID, F_CHANNEL,
            F_STATUS, F_CREATED_AT, F_IDLE_EXPIRES_AT, F_ABSOLUTE_EXPIRES_AT, F_SESSION_VERSION, F_SECRET,
            F_DEVICE_KEY_JWK, F_DEVICE_KEY_JKT);

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
        if (session.deviceKey() != null) {
            fields.put(F_DEVICE_KEY_JWK, session.deviceKey().publicJwk());
            fields.put(F_DEVICE_KEY_JKT, session.deviceKey().thumbprint());
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
        boolean deviceKeyIsWhole = fields.containsKey(F_DEVICE_KEY_JWK) == fields.containsKey(F_DEVICE_KEY_JKT);
        if (!hasEveryRequiredField || !hasOnlyKnownFields || !isCurrentSchema || !deviceKeyIsWhole) {
            return Optional.empty();
        }

        try {
            String deviceId = fields.get(F_DEVICE_ID);
            String deviceKeyJwk = fields.get(F_DEVICE_KEY_JWK);
            DeviceSigningKey deviceKey = deviceKeyJwk == null
                    ? null
                    : new DeviceSigningKey(deviceKeyJwk, fields.get(F_DEVICE_KEY_JKT));

            Session session = Session.builder()
                    .id(new SessionId(UUID.fromString(fields.get(F_SESSION_ID))))
                    .customerId(new CustomerId(fields.get(F_CUSTOMER_ID)))
                    .deviceId(deviceId == null ? null : new DeviceId(deviceId))
                    .channel(Channel.valueOf(fields.get(F_CHANNEL)))
                    .status(SessionStatus.valueOf(fields.get(F_STATUS)))
                    .createdAt(instant(fields.get(F_CREATED_AT)))
                    .idleExpiresAt(instant(fields.get(F_IDLE_EXPIRES_AT)))
                    .absoluteExpiresAt(instant(fields.get(F_ABSOLUTE_EXPIRES_AT)))
                    .sessionVersion(Long.parseLong(fields.get(F_SESSION_VERSION)))
                    .deviceKey(deviceKey)
                    .build();
            return Optional.of(session);
        } catch (IllegalArgumentException malformed) {
            return Optional.empty();
        }
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
