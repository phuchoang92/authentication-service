package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.DomainFixtures;
import com.vpbank.dcp.auth.domain.model.NewSession;
import com.vpbank.dcp.auth.domain.model.OpaqueToken;
import com.vpbank.dcp.auth.domain.model.Session;
import com.vpbank.dcp.auth.domain.model.SessionId;
import com.vpbank.dcp.auth.domain.model.SessionPolicy;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import static org.assertj.core.api.Assertions.assertThat;


/**
 * The session record is a contract shared with the BFF: both test suites run the vectors in
 * {@code docs/DD/target/reference/session-record-vectors.json} (doc 22).
 */
class SessionJsonCodecTest {
    private static final Path VECTORS =
            Path.of("..", "docs", "DD", "target", "reference", "session-record-vectors.json");

    private final SessionJsonCodec codec = new SessionJsonCodec(SessionJsonCodec.strictJson());
    private final SessionKeys keys = new SessionKeys();
    private final JsonNode vectors = readVectors();

    @Test
    void anAcceptedVectorDecodesToItsSessionAndEncodesBackToItsText() {
        assertThat(vectors.get("accepted")).isNotEmpty();
        for (JsonNode vector : vectors.get("accepted")) {
            String name = vector.get("name").stringValue();
            JsonNode expected = vector.get("session");
            SessionRecord record = codec.decode(vector.get("text").stringValue())
                    .orElseThrow(() -> new AssertionError(name));

            Session session = record.session();
            assertThat(session.id().value().toString()).as(name).isEqualTo(expected.get("sessionId").stringValue());
            assertThat(session.customerId().value()).as(name).isEqualTo(expected.get("customerId").stringValue());
            assertThat(session.deviceId() == null ? null : session.deviceId().value()).as(name)
                    .isEqualTo(expected.get("deviceId").isNull() ? null : expected.get("deviceId").stringValue());
            assertThat(session.channel().name()).as(name).isEqualTo(expected.get("channel").stringValue());
            assertThat(session.status().name()).as(name).isEqualTo(expected.get("status").stringValue());
            assertThat(session.createdAt().toEpochMilli()).as(name).isEqualTo(expected.get("createdAtMs").longValue());
            assertThat(session.idleExpiresAt().toEpochMilli()).as(name)
                    .isEqualTo(expected.get("idleExpiresAtMs").longValue());
            assertThat(session.absoluteExpiresAt().toEpochMilli()).as(name)
                    .isEqualTo(expected.get("absoluteExpiresAtMs").longValue());
            assertThat(session.sessionVersion()).as(name).isEqualTo(expected.get("sessionVersion").longValue());
            assertThat(record.secretDigest()).as(name).isEqualTo(vector.get("secretDigest").stringValue());

            assertThat(codec.encode(record)).as(name).isEqualTo(vector.get("text").stringValue());
        }
    }

    @Test
    void anAcceptedVectorsTokenGivesItsKeyAndItsSecretDigest() {
        for (JsonNode vector : vectors.get("accepted")) {
            String name = vector.get("name").stringValue();
            OpaqueToken token = new OpaqueToken(vector.get("token").stringValue());

            assertThat(keys.forLookup(keys.lookupOf(token))).as(name).isEqualTo(vector.get("key").stringValue());
            String digest = vector.get("secretDigest").stringValue();
            assertThat(SessionSecretDigest.of(token.secret())).as(name).isEqualTo(digest);
            assertThat(SessionSecretDigest.matches(digest, token.secret())).as(name).isTrue();
            assertThat(SessionSecretDigest.matches(digest, "x".repeat(43))).as(name).isFalse();
        }
    }

    @Test
    void aRejectedVectorIsNoSession() {
        assertThat(vectors.get("rejected")).isNotEmpty();
        for (JsonNode vector : vectors.get("rejected")) {
            assertThat(codec.decode(vector.get("text").stringValue())).as(vector.get("name").stringValue()).isEmpty();
        }
        assertThat(codec.decode(null)).isEmpty();
        assertThat(codec.decode("")).isEmpty();
    }

    @Test
    void aFreshSessionEncodesTheSameWayAsItsReadBackCopy() {
        NewSession start = DomainFixtures.mobileSession(SessionId.random(), new CustomerId("90359"),
                new DeviceId("dev-1"), Instant.parse("2026-10-25T10:00:00.123456789Z"));
        Session session = Session.start(start, new SessionPolicy(Duration.ofMinutes(15), Duration.ofMinutes(20),
                Duration.ofSeconds(30)));
        SessionRecord fresh = new SessionRecord(session, SessionSecretDigest.of("A".repeat(43)));

        String text = codec.encode(fresh);
        SessionRecord readBack = codec.decode(text).orElseThrow();

        assertThat(codec.encode(readBack)).isEqualTo(text); // finer than a millisecond is not stored
        assertThat(text).doesNotContain("A".repeat(43));
    }

    private static JsonNode readVectors() {
        try {
            return JsonMapper.builder().build().readTree(Files.readString(VECTORS));
        } catch (IOException missing) {
            throw new IllegalStateException("The shared vectors are at " + VECTORS.toAbsolutePath(), missing);
        }
    }
}
