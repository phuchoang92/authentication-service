package com.vpbank.dcp.infrastructure.adapter.out.redis.codec;

import java.time.Instant;
import java.util.Map;
import java.util.Set;

/**
 * Exact UTF-8 Redis HASH schema; no Java serialization or unknown-field tolerance.
 */
public final class ServingControlCodec {

    private static final Set<String> FIELDS = Set.of(
            "schemaVersion", "state", "generation", "redisRunId", "controllerId",
            "controllerFence", "leaseUntilMs");

    public Map<String, String> encode(ServingControlSnapshot value) {
        return Map.of(
                "schemaVersion", "1",
                "state", value.state().code(),
                "generation", value.generation().toString(),
                "redisRunId", value.redisRunId(),
                "controllerId", value.controllerId().toString(),
                "controllerFence", AuthorityNumberCodec.encode(value.controllerFence()),
                "leaseUntilMs", AuthorityNumberCodec.encode(value.leaseUntil().toEpochMilli()));
    }

    public ServingControlSnapshot decode(Map<Object, Object> stored) {
        if (stored == null || stored.size() != FIELDS.size()
                || !stored.keySet().equals(FIELDS)
                || !"1".equals(stored.get("schemaVersion"))) {
            throw new InvalidAuthorityValueException();
        }
        return new ServingControlSnapshot(
                ServingState.fromCode(text(stored, "state")),
                AuthorityUuidCodec.decode(text(stored, "generation")),
                text(stored, "redisRunId"),
                AuthorityUuidCodec.decode(text(stored, "controllerId")),
                AuthorityNumberCodec.decode(text(stored, "controllerFence")),
                Instant.ofEpochMilli(AuthorityNumberCodec.decode(text(stored, "leaseUntilMs"))));
    }

    private String text(Map<Object, Object> stored, String field) {
        if (!(stored.get(field) instanceof String value)) {
            throw new InvalidAuthorityValueException();
        }
        return value;
    }
}
