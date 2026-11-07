package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

import static org.assertj.core.api.Assertions.assertThat;

import com.vpbank.dcp.auth.application.port.out.model.CacheTransaction;
import com.vpbank.dcp.auth.application.port.out.model.TransactionKind;
import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.DevicePlatform;
import com.vpbank.dcp.auth.domain.enums.SessionStatus;
import com.vpbank.dcp.auth.domain.model.AdmittedSession;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.DeviceKey;
import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import com.vpbank.dcp.auth.domain.model.EnrollmentTransaction;
import com.vpbank.dcp.auth.domain.model.KeyExchangeStart;
import com.vpbank.dcp.auth.domain.model.SessionId;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import org.junit.jupiter.api.Test;

/** The envelope is five string fields; the payload is one JSON field read back strictly into the flow's record. */
class TransactionJsonCodecTest {
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
    private final TransactionJsonCodec codec = new TransactionJsonCodec(TransactionJsonCodec.strictPayloadJson());
    private final CacheTransaction<SamplePayload> transaction = KIND.open("MOBILE:90359:tablet-2", EXPIRES,
            new SamplePayload(new CustomerId("90359"), SamplePayload.Step.STARTED, List.of("a", "b"), null, 1));
    private final String text = codec.encode(transaction);

    @Test
    void theTextIsTheEnvelopeInAFixedOrderWithThePayloadInside() {
        assertThat(text).isEqualTo("{\"schemaVersion\":2,\"purpose\":\"sample\",\"expiresAtMs\":1793787000123,\"version\":0,"
                + "\"payload\":{\"customerId\":{\"value\":\"90359\"},\"step\":\"STARTED\",\"notes\":[\"a\",\"b\"],"
                + "\"optional\":null,\"attempts\":1}}");
        assertThat(codec.decode(KIND, "MOBILE:90359:tablet-2", text)).contains(transaction);

        CacheTransaction<SamplePayload> later = transaction
                .next(new SamplePayload(new CustomerId("90359"), SamplePayload.Step.PROVEN, List.of(), "x", 2));
        assertThat(codec.decode(KIND, later.id(), codec.encode(later))).contains(later);
    }

    /** The store's compare-and-set compares texts, so what was read must encode to what was stored. */
    @Test
    void equalTransactionsGiveTheSameTextAlsoAfterBeingReadBack() {
        CacheTransaction<SamplePayload> sameValues = KIND.open("MOBILE:90359:tablet-2", EXPIRES.plusNanos(999),
                new SamplePayload(new CustomerId("90359"), SamplePayload.Step.STARTED, List.of("a", "b"), null, 1));
        assertThat(codec.encode(sameValues)).isEqualTo(text); // finer than a millisecond is not stored

        CacheTransaction<SamplePayload> readBack = codec.decode(KIND, transaction.id(), text).orElseThrow();
        assertThat(codec.encode(readBack)).isEqualTo(text);

        // Every saved state differs from the one before, even when the payload returns to an earlier value.
        CacheTransaction<SamplePayload> movedAndBack = transaction.next(transaction.payload());
        assertThat(codec.encode(movedAndBack)).isNotEqualTo(text);
    }

    /** The payload of the real flow: a text it was decoded from is the text it encodes to. */
    @Test
    void anEnrollmentReadBackEncodesToTheStoredText() {
        TransactionKind<EnrollmentTransaction> enrollments = new TransactionKind<>("enrollment", EnrollmentTransaction.class);
        AdmittedSession tabletSession = new AdmittedSession(SessionId.random(), new CustomerId("90359"), Channel.MOBILE,
                new DeviceId("tablet-2"), SessionStatus.NEED_TRUSTED_DEVICE);
        KeyExchangeStart start = KeyExchangeStart.builder()
                .enrollmentId(EnrollmentId.random())
                .newDeviceSession(tabletSession)
                .deviceKey(new DeviceKey("{\"kty\":\"EC\"}", DevicePlatform.IOS))
                .serverPublicJwk("{srv-pub}")
                .serverPrivateJwk("{srv-priv}")
                .challengeDigest("digest")
                .build();
        CacheTransaction<EnrollmentTransaction> opened =
                enrollments.open("MOBILE:90359:tablet-2", EXPIRES, EnrollmentTransaction.keyExchange(start));
        CacheTransaction<EnrollmentTransaction> mfaRequired =
                opened.next(opened.payload().countVerifyAttempt().markMfaRequired("mfa-1"));

        for (CacheTransaction<EnrollmentTransaction> state : List.of(opened, mfaRequired)) {
            String stored = codec.encode(state);
            CacheTransaction<EnrollmentTransaction> readBack = codec.decode(enrollments, state.id(), stored).orElseThrow();
            assertThat(readBack).isEqualTo(state);
            assertThat(codec.encode(readBack)).isEqualTo(stored);
        }
    }

    @Test
    void anythingUnexpectedDecodesToNoTransaction() {
        assertThat(codec.decode(KIND, "id", null)).isEmpty();
        assertThat(codec.decode(KIND, "id", "")).isEmpty();
        assertThat(codec.decode(KIND, "id", "not json")).isEmpty();
        assertThat(codec.decode(KIND, "id", "[" + text + "]")).isEmpty();
        assertThat(codec.decode(KIND, "id", text.replace("\"version\":0,", ""))).isEmpty();                    // a property missing
        assertThat(codec.decode(KIND, "id", text.replace("\"version\":0,", "\"version\":0,\"extra\":1,"))).isEmpty();
        assertThat(codec.decode(KIND, "id", text.replace("\"schemaVersion\":2", "\"schemaVersion\":1"))).isEmpty();
        assertThat(codec.decode(KIND, "id", text.replace("\"schemaVersion\":2", "\"schemaVersion\":\"2\""))).isEmpty();
        assertThat(codec.decode(KIND, "id", text.replace("\"purpose\":\"sample\"", "\"purpose\":\"other-flow\""))).isEmpty(); // not this kind
        assertThat(codec.decode(KIND, "id", text.replace("\"version\":0", "\"version\":-1"))).isEmpty();
        assertThat(codec.decode(KIND, "id", text.replace("\"version\":0", "\"version\":\"0\""))).isEmpty();
        assertThat(codec.decode(KIND, "id", text.replace("\"version\":0", "\"version\":0.5"))).isEmpty();
        assertThat(codec.decode(KIND, "id", text.replace("1793787000123", "-5"))).isEmpty();
        assertThat(codec.decode(KIND, "id",
                "{\"schemaVersion\":2,\"purpose\":\"sample\",\"expiresAtMs\":1,\"version\":0,\"payload\":null}")).isEmpty();
        // Strict payload: an unknown property, a value the record refuses, a wrong type.
        assertThat(codec.decode(KIND, "id", text.replace("\"attempts\":1", "\"attempts\":1,\"x\":1"))).isEmpty();
        assertThat(codec.decode(KIND, "id", text.replace("\"attempts\":1", "\"attempts\":-1"))).isEmpty();
        assertThat(codec.decode(KIND, "id", text.replace("\"step\":\"STARTED\"", "\"step\":\"DONE\""))).isEmpty();
        assertThat(codec.decode(KIND, "id", text.replace("{\"value\":\"90359\"}", "null"))).isEmpty();
        assertThat(codec.decode(KIND, "id", text.replace("\"attempts\":1", "\"attempts\":null"))).isEmpty();
    }
}
