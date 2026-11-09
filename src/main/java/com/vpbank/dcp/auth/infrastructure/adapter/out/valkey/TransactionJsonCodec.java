package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

import com.vpbank.dcp.auth.application.port.out.model.CacheTransaction;
import com.vpbank.dcp.auth.application.port.out.model.TransactionKind;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.SerializationFeature;
import tools.jackson.databind.cfg.DateTimeFeature;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * Cache transaction ↔ the one JSON text Valkey keeps for it:
 * {@code {"schemaVersion":4,"purpose":…,"expiresAtMs":…,"payload":{…}}}. The envelope is four fixed properties in
 * that order; the payload is the flow's own record, so this codec serves every flow without knowing any. Schema 3
 * dropped the {@code version} counter of schema 2: the store compares the whole text, so the payload is enough.
 * Schema 4 has the same envelope; the enrollment payload gained the answers init and verify repeat.
 *
 * <p>Encoding is deterministic: equal transactions give the same text. The store relies on it, because its
 * compare-and-set asks Valkey whether the stored text still equals the text of the transaction the caller read.
 * A payload type must therefore encode the same way every time (records of values do; an unordered set would
 * not). A mismatch can only refuse a write, never accept a stale one.
 *
 * <p>Decoding is strict: a missing or unknown envelope property, a value of the wrong type, a purpose other than
 * the one asked for, or a payload with an unknown or missing property means "no transaction", never a guessed
 * default. The payload is written as it is: a flow that keeps a secret there keeps it unencrypted.
 */
@RequiredArgsConstructor
public final class TransactionJsonCodec {
    static final int SCHEMA_VERSION = 4;
    static final String P_SCHEMA = "schemaVersion";
    static final String P_PURPOSE = "purpose";
    static final String P_EXPIRES_AT = "expiresAtMs";
    static final String P_PAYLOAD = "payload";
    private static final Set<String> PROPERTIES = Set.of(P_SCHEMA, P_PURPOSE, P_EXPIRES_AT, P_PAYLOAD);

    @NonNull
    private final JsonMapper payloadJson;

    /**
     * A mapper that accepts exactly the payload record's properties, writes times as ISO-8601 text and map
     * entries in key order (so equal payloads give equal text).
     */
    public static JsonMapper strictPayloadJson() {
        return JsonMapper.builder()
                .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
                .enable(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES)
                .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS)
                .disable(DateTimeFeature.WRITE_DATES_AS_TIMESTAMPS)
                .build();
    }

    public String encode(@NonNull CacheTransaction<?> transaction) {
        ObjectNode envelope = payloadJson.createObjectNode();
        envelope.put(P_SCHEMA, SCHEMA_VERSION);
        envelope.put(P_PURPOSE, transaction.kind().purpose());
        envelope.put(P_EXPIRES_AT, transaction.expiresAt().toEpochMilli());
        envelope.set(P_PAYLOAD, payloadJson.valueToTree(transaction.payload()));
        return payloadJson.writeValueAsString(envelope);
    }

    public <P> Optional<CacheTransaction<P>> decode(@NonNull TransactionKind<P> kind, @NonNull String id, String text) {
        if (text == null) {
            return Optional.empty();
        }
        try {
            JsonNode envelope = payloadJson.readTree(text);
            if (!isEnvelopeOf(kind, envelope)) {
                return Optional.empty();
            }
            Instant expiresAt = Instant.ofEpochMilli(nonNegative(envelope.get(P_EXPIRES_AT)));
            P payload = payloadJson.treeToValue(envelope.get(P_PAYLOAD), kind.payloadType());
            if (payload == null) {
                return Optional.empty();
            }
            return Optional.of(new CacheTransaction<>(kind, id, expiresAt, payload));
        } catch (IllegalArgumentException | JacksonException malformed) {
            // Text that is not JSON, a number out of range, a payload record refusing its values.
            return Optional.empty();
        }
    }

    /** Exactly the four properties, this schema, and the purpose the caller asked for. */
    private static boolean isEnvelopeOf(TransactionKind<?> kind, JsonNode envelope) {
        if (!envelope.isObject() || !PROPERTIES.equals(Set.copyOf(envelope.propertyNames()))) {
            return false;
        }
        JsonNode schemaVersion = envelope.get(P_SCHEMA);
        JsonNode purpose = envelope.get(P_PURPOSE);
        boolean isThisSchema = schemaVersion.isIntegralNumber() && schemaVersion.longValue() == SCHEMA_VERSION;
        boolean isThisKind = purpose.isString() && kind.purpose().equals(purpose.stringValue());
        return isThisSchema && isThisKind;
    }

    private static long nonNegative(JsonNode number) {
        if (!number.isIntegralNumber() || !number.canConvertToLong() || number.longValue() < 0) {
            throw new IllegalArgumentException("Not a non-negative whole number");
        }
        return number.longValue();
    }
}
