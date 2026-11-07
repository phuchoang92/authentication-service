package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.SessionStatus;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.Session;
import com.vpbank.dcp.auth.domain.model.SessionId;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import tools.jackson.core.JacksonException;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * Session ↔ the one JSON text Valkey keeps for it (doc 22, decided 2026-11-07), properties in this fixed order:
 * {@code schemaVersion}, {@code sessionId}, {@code customerId}, {@code deviceId} (explicit {@code null} on WEB),
 * {@code channel}, {@code status}, {@code createdAtMs}, {@code idleExpiresAtMs}, {@code absoluteExpiresAtMs},
 * {@code sessionVersion}, {@code secretDigest}. Times are UTC milliseconds, codes upper case, no whitespace.
 *
 * <p>Encoding is deterministic: equal records give the same text, which the store's compare-and-set relies on.
 * Decoding is strict, here and in the BFF: text that is not an object, a property missing, unknown or repeated, a
 * value of the wrong type or outside its format, or an unknown schema version means "no session", never a guessed
 * default. The token's secret itself is never stored, only its digest.
 */
@RequiredArgsConstructor
public final class SessionJsonCodec {
    static final int SCHEMA_VERSION = 2;
    static final String P_SCHEMA = "schemaVersion";
    static final String P_SESSION_ID = "sessionId";
    static final String P_CUSTOMER_ID = "customerId";
    static final String P_DEVICE_ID = "deviceId";
    static final String P_CHANNEL = "channel";
    static final String P_STATUS = "status";
    static final String P_CREATED_AT = "createdAtMs";
    static final String P_IDLE_EXPIRES_AT = "idleExpiresAtMs";
    static final String P_ABSOLUTE_EXPIRES_AT = "absoluteExpiresAtMs";
    static final String P_SESSION_VERSION = "sessionVersion";
    static final String P_SECRET_DIGEST = "secretDigest";
    private static final Set<String> PROPERTIES = Set.of(P_SCHEMA, P_SESSION_ID, P_CUSTOMER_ID, P_DEVICE_ID, P_CHANNEL,
            P_STATUS, P_CREATED_AT, P_IDLE_EXPIRES_AT, P_ABSOLUTE_EXPIRES_AT, P_SESSION_VERSION, P_SECRET_DIGEST);

    @NonNull
    private final JsonMapper json;

    /** A mapper that refuses a repeated property name; nothing else of Jackson's defaults matters here. */
    public static JsonMapper strictJson() {
        return JsonMapper.builder()
                .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
                .build();
    }

    public String encode(@NonNull SessionRecord record) {
        Session session = record.session();
        ObjectNode text = json.createObjectNode();
        text.put(P_SCHEMA, SCHEMA_VERSION);
        text.put(P_SESSION_ID, session.id().value().toString());
        text.put(P_CUSTOMER_ID, session.customerId().value());
        if (session.deviceId() == null) {
            text.putNull(P_DEVICE_ID);
        } else {
            text.put(P_DEVICE_ID, session.deviceId().value());
        }
        text.put(P_CHANNEL, session.channel().name());
        text.put(P_STATUS, session.status().name());
        text.put(P_CREATED_AT, session.createdAt().toEpochMilli());
        text.put(P_IDLE_EXPIRES_AT, session.idleExpiresAt().toEpochMilli());
        text.put(P_ABSOLUTE_EXPIRES_AT, session.absoluteExpiresAt().toEpochMilli());
        text.put(P_SESSION_VERSION, session.sessionVersion());
        text.put(P_SECRET_DIGEST, record.secretDigest());
        return json.writeValueAsString(text);
    }

    public Optional<SessionRecord> decode(String text) {
        if (text == null) {
            return Optional.empty();
        }
        try {
            JsonNode record = json.readTree(text);
            if (!isSessionRecord(record)) {
                return Optional.empty();
            }
            return Optional.of(new SessionRecord(sessionOf(record), string(record, P_SECRET_DIGEST)));
        } catch (IllegalArgumentException | JacksonException malformed) {
            // Not JSON, a repeated property, a wrong type, a value a domain object refuses.
            return Optional.empty();
        }
    }

    /** Exactly the eleven properties and this schema; the values are checked while the session is built. */
    private static boolean isSessionRecord(JsonNode record) {
        if (!record.isObject() || !PROPERTIES.equals(Set.copyOf(record.propertyNames()))) {
            return false;
        }
        JsonNode schemaVersion = record.get(P_SCHEMA);
        return schemaVersion.isIntegralNumber() && schemaVersion.longValue() == SCHEMA_VERSION;
    }

    private static Session sessionOf(JsonNode record) {
        JsonNode deviceId = record.get(P_DEVICE_ID);
        if (!deviceId.isNull() && !deviceId.isString()) {
            throw new IllegalArgumentException("deviceId is text or null");
        }
        return Session.builder()
                .id(new SessionId(UUID.fromString(string(record, P_SESSION_ID))))
                .customerId(new CustomerId(string(record, P_CUSTOMER_ID)))
                .deviceId(deviceId.isNull() ? null : new DeviceId(deviceId.stringValue()))
                .channel(Channel.valueOf(string(record, P_CHANNEL)))
                .status(SessionStatus.valueOf(string(record, P_STATUS)))
                .createdAt(instant(record, P_CREATED_AT))
                .idleExpiresAt(instant(record, P_IDLE_EXPIRES_AT))
                .absoluteExpiresAt(instant(record, P_ABSOLUTE_EXPIRES_AT))
                .sessionVersion(wholeNumber(record, P_SESSION_VERSION))
                .build();
    }

    private static String string(JsonNode record, String property) {
        JsonNode value = record.get(property);
        if (!value.isString()) {
            throw new IllegalArgumentException(property + " is text");
        }
        return value.stringValue();
    }

    private static Instant instant(JsonNode record, String property) {
        return Instant.ofEpochMilli(wholeNumber(record, property));
    }

    private static long wholeNumber(JsonNode record, String property) {
        JsonNode value = record.get(property);
        if (!value.isIntegralNumber() || !value.canConvertToLong() || value.longValue() < 0) {
            throw new IllegalArgumentException(property + " is a non-negative whole number");
        }
        return value.longValue();
    }
}
