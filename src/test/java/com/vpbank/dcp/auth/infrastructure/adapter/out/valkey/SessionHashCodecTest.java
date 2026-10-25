package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

import static org.assertj.core.api.Assertions.assertThat;

import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.DevicePlatform;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.DevicePolicy;
import com.vpbank.dcp.auth.domain.model.EnrollmentContext;
import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import com.vpbank.dcp.auth.domain.model.Session;
import com.vpbank.dcp.auth.domain.model.SessionId;
import com.vpbank.dcp.auth.domain.model.SessionPolicy;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class SessionHashCodecTest {
    private final Session session = Session.start(new SessionId(UUID.fromString("22222222-2222-4222-8222-222222222222")),
            new CustomerId("90359"), new DeviceId("dev-1"), Channel.MOBILE, Instant.parse("2026-10-25T10:00:00.123Z"),
            new SessionPolicy(Duration.ofMinutes(15), Duration.ofMinutes(20), Duration.ofSeconds(30)));

    @Test
    void roundTripsWithStringFieldsOnly() {
        Map<String, String> fields = SessionHashCodec.encode(session);

        assertThat(fields).containsEntry("schemaVersion", "1").containsEntry("customerId", "90359")
                .containsEntry("deviceId", "dev-1").containsEntry("channel", "MOBILE").containsEntry("status", "ACTIVE")
                .containsEntry("createdAtMs", "1792922400123").containsEntry("sessionVersion", "0");
        assertThat(fields.keySet()).noneMatch(k -> k.toLowerCase().contains("token"));
        assertThat(SessionHashCodec.decode(fields)).contains(session);
        assertThat(SessionHashCodec.decode(SessionHashCodec.encode(session.toBuilder().deviceId(null).build())))
                .hasValueSatisfying(s -> assertThat(s.deviceId()).isNull());
    }

    @Test
    void aRestrictedSessionCarriesItsEnrollmentContextAllOrNothing() {
        Session restricted = Session.startRestricted(SessionId.random(), new CustomerId("90359"), new DeviceId("tablet-2"),
                Channel.MOBILE, Instant.parse("2026-10-25T10:00:00Z"), DevicePolicy.standard())
                .withEnrollment(EnrollmentContext.builder().enrollmentId(EnrollmentId.random()).devicePublicJwk("{dev}")
                        .platform(DevicePlatform.IOS).serverPublicJwk("{pub}").serverPrivateJwk("{priv}")
                        .challengeDigest("digest").keyProven(true).build());
        Map<String, String> fields = SessionHashCodec.encode(restricted);
        assertThat(fields).containsEntry("status", "NEED_TRUSTED_DEVICE").containsEntry("keyProven", "1")
                .containsEntry("serverPrivateJwk", "{priv}");
        assertThat(SessionHashCodec.decode(fields)).contains(restricted);
        assertThat(SessionHashCodec.decode(without(fields, "serverPrivateJwk"))).isEmpty(); // partial context = no session
        assertThat(SessionHashCodec.decode(with(fields, "keyProven", "yes"))).isEmpty();
        assertThat(SessionHashCodec.decode(SessionHashCodec.encode(session))).hasValueSatisfying(s ->
                assertThat(s.enrollment()).isNull());
    }

    @Test
    void anythingUnexpectedDecodesToNoSession() {
        Map<String, String> fields = SessionHashCodec.encode(session);
        assertThat(SessionHashCodec.decode(without(fields, "status"))).isEmpty();
        assertThat(SessionHashCodec.decode(with(fields, "schemaVersion", "2"))).isEmpty();
        assertThat(SessionHashCodec.decode(with(fields, "extra", "x"))).isEmpty();
        assertThat(SessionHashCodec.decode(with(fields, "idleExpiresAtMs", "soon"))).isEmpty();
        assertThat(SessionHashCodec.decode(with(fields, "channel", "FAX"))).isEmpty();
        assertThat(SessionHashCodec.decode(with(fields, "customerId", "not valid!"))).isEmpty();
        assertThat(SessionHashCodec.decode(Map.of())).isEmpty();
    }

    private static Map<String, String> without(Map<String, String> fields, String key) {
        Map<String, String> copy = new HashMap<>(fields);
        copy.remove(key);
        return copy;
    }

    private static Map<String, String> with(Map<String, String> fields, String key, String value) {
        Map<String, String> copy = new HashMap<>(fields);
        copy.put(key, value);
        return copy;
    }
}
