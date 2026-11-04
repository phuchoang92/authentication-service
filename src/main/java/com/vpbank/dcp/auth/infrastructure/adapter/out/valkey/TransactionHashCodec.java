package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

import com.vpbank.dcp.auth.application.port.out.model.CacheTransaction;
import com.vpbank.dcp.auth.application.port.out.model.TransactionKind;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.MapperFeature;
import tools.jackson.databind.cfg.DateTimeFeature;
import tools.jackson.databind.json.JsonMapper;

import java.time.Instant;
import java.util.*;

/**
 * Cache transaction ↔ Valkey HASH fields (contract 16 style: every field a UTF-8 string, integers base-10,
 * {@code schemaVersion=1}). The envelope is five fixed fields; the payload is one field holding its JSON, so
 * this codec serves every flow without knowing any. Decoding is strict: a missing or unknown envelope field, a
 * value that does not parse, a purpose other than the one asked for, or a payload JSON with an unknown or
 * missing property means "no transaction", never a guessed default. The payload is written as it is: a flow
 * that keeps a secret there keeps it unencrypted (as the restricted session did until slice 11).
 */
public final class TransactionHashCodec {
    static final String SCHEMA_VERSION = "1";
    static final String F_SCHEMA = "schemaVersion";
    static final String F_PURPOSE = "purpose";
    static final String F_EXPIRES_AT = "expiresAtMs";
    static final String F_VERSION = "version";
    static final String F_PAYLOAD = "payload";
    private static final Set<String> FIELDS = Set.of(F_SCHEMA, F_PURPOSE, F_EXPIRES_AT, F_VERSION, F_PAYLOAD);

    private final JsonMapper payloadJson;

    /**
     * A mapper that accepts exactly the payload record's properties and writes times as ISO-8601 text.
     */
    public static JsonMapper strictPayloadJson() {
        return JsonMapper.builder()
                .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
                .enable(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES)
                .disable(DateTimeFeature.WRITE_DATES_AS_TIMESTAMPS)
                .disable(MapperFeature.AUTO_DETECT_GETTERS)
                .disable(MapperFeature.AUTO_DETECT_IS_GETTERS)
                .build();
    }

    public TransactionHashCodec(JsonMapper payloadJson) {
        this.payloadJson = Objects.requireNonNull(payloadJson, "payloadJson");
    }

    public Map<String, String> encode(CacheTransaction<?> transaction) {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put(F_SCHEMA, SCHEMA_VERSION);
        fields.put(F_PURPOSE, transaction.kind().purpose());
        fields.put(F_EXPIRES_AT, Long.toString(transaction.expiresAt().toEpochMilli()));
        fields.put(F_VERSION, Long.toString(transaction.version()));
        fields.put(F_PAYLOAD, payloadJson.writeValueAsString(transaction.payload()));
        return fields;
    }

    public <P> Optional<CacheTransaction<P>> decode(TransactionKind<P> kind, String id, Map<String, String> fields) {
        if (fields == null) {
            return Optional.empty();
        }
        boolean hasExactlyTheFields = FIELDS.equals(fields.keySet());
        boolean isCurrentSchema = SCHEMA_VERSION.equals(fields.get(F_SCHEMA));
        boolean isThisKind = kind.purpose().equals(fields.get(F_PURPOSE));
        if (!hasExactlyTheFields || !isCurrentSchema || !isThisKind) {
            return Optional.empty();
        }

        try {
            Instant expiresAt = instant(fields.get(F_EXPIRES_AT));
            long version = Long.parseLong(fields.get(F_VERSION));
            P payload = payloadJson.readValue(fields.get(F_PAYLOAD), kind.payloadType());
            if (payload == null) {
                return Optional.empty();
            }
            return Optional.of(new CacheTransaction<>(kind, id, expiresAt, version, payload));
        } catch (IllegalArgumentException | JacksonException malformed) {
            // NumberFormatException, a payload record refusing its values, or JSON that is not that record.
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
