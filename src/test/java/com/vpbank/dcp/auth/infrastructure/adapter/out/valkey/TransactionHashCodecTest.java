package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

import static org.assertj.core.api.Assertions.assertThat;

import com.vpbank.dcp.auth.application.port.out.model.CacheTransaction;
import com.vpbank.dcp.auth.application.port.out.model.TransactionKind;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.junit.jupiter.api.Test;

/** The envelope is five string fields; the payload is one JSON field read back strictly into the flow's record. */
class TransactionHashCodecTest {
    /** A payload as any flow might declare one: value objects, an enum, a list, a nullable, a required field. */
    record SamplePayload(CustomerId customerId, Step step, List<String> notes, String optional, int attempts) {
        enum Step { STARTED, PROVEN }

        SamplePayload {
            Objects.requireNonNull(customerId, "customerId");
            if (attempts < 0) {
                throw new IllegalArgumentException("attempts");
            }
        }
    }

    private static final TransactionKind<SamplePayload> KIND = new TransactionKind<>("sample", SamplePayload.class);
    private static final Instant EXPIRES = Instant.parse("2026-11-04T10:10:00.123Z");
    private final TransactionHashCodec codec = new TransactionHashCodec(TransactionHashCodec.strictPayloadJson());
    private final CacheTransaction<SamplePayload> transaction = CacheTransaction.open(KIND, "MOBILE:90359:tablet-2", EXPIRES,
            new SamplePayload(new CustomerId("90359"), SamplePayload.Step.STARTED, List.of("a", "b"), null, 1));

    @Test
    void roundTripsWithAnEnvelopeOfStringsAndThePayloadAsJson() {
        Map<String, String> fields = codec.encode(transaction);

        assertThat(fields).containsEntry("schemaVersion", "1").containsEntry("purpose", "sample")
                .containsEntry("expiresAtMs", "1793787000123").containsEntry("version", "0")
                .containsOnlyKeys("schemaVersion", "purpose", "expiresAtMs", "version", "payload");
        assertThat(fields.get("payload")).contains("\"customerId\":{\"value\":\"90359\"}").contains("\"step\":\"STARTED\"")
                .contains("\"notes\":[\"a\",\"b\"]").contains("\"optional\":null").contains("\"attempts\":1");
        assertThat(codec.decode(KIND, "MOBILE:90359:tablet-2", fields)).contains(transaction);

        CacheTransaction<SamplePayload> later = transaction.withVersion(3)
                .withPayload(new SamplePayload(new CustomerId("90359"), SamplePayload.Step.PROVEN, List.of(), "x", 2));
        assertThat(codec.decode(KIND, later.id(), codec.encode(later))).contains(later);
    }

    @Test
    void anythingUnexpectedDecodesToNoTransaction() {
        Map<String, String> fields = codec.encode(transaction);

        assertThat(codec.decode(KIND, "id", null)).isEmpty();
        assertThat(codec.decode(KIND, "id", without(fields, "payload"))).isEmpty();
        assertThat(codec.decode(KIND, "id", without(fields, "version"))).isEmpty();
        assertThat(codec.decode(KIND, "id", with(fields, "extra", "x"))).isEmpty();
        assertThat(codec.decode(KIND, "id", with(fields, "schemaVersion", "2"))).isEmpty();
        assertThat(codec.decode(KIND, "id", with(fields, "purpose", "other-flow"))).isEmpty();     // not this kind
        assertThat(codec.decode(KIND, "id", with(fields, "version", "-1"))).isEmpty();
        assertThat(codec.decode(KIND, "id", with(fields, "version", "two"))).isEmpty();
        assertThat(codec.decode(KIND, "id", with(fields, "expiresAtMs", "-5"))).isEmpty();
        assertThat(codec.decode(KIND, "id", with(fields, "payload", "not json"))).isEmpty();
        assertThat(codec.decode(KIND, "id", with(fields, "payload", "null"))).isEmpty();
        // Strict payload: an unknown property, a value the record refuses, a wrong type.
        assertThat(codec.decode(KIND, "id", with(fields, "payload", fields.get("payload").replace("\"attempts\":1", "\"attempts\":1,\"x\":1")))).isEmpty();
        assertThat(codec.decode(KIND, "id", with(fields, "payload", fields.get("payload").replace("\"attempts\":1", "\"attempts\":-1")))).isEmpty();
        assertThat(codec.decode(KIND, "id", with(fields, "payload", fields.get("payload").replace("\"step\":\"STARTED\"", "\"step\":\"DONE\"")))).isEmpty();
        assertThat(codec.decode(KIND, "id", with(fields, "payload", fields.get("payload").replace("{\"value\":\"90359\"}", "null")))).isEmpty();
        assertThat(codec.decode(KIND, "id", with(fields, "payload", fields.get("payload").replace("\"attempts\":1", "\"attempts\":null")))).isEmpty();
    }

    private static Map<String, String> with(Map<String, String> fields, String name, String value) {
        Map<String, String> changed = new HashMap<>(fields);
        changed.put(name, value);
        return changed;
    }

    private static Map<String, String> without(Map<String, String> fields, String name) {
        Map<String, String> changed = new HashMap<>(fields);
        changed.remove(name);
        return changed;
    }
}
