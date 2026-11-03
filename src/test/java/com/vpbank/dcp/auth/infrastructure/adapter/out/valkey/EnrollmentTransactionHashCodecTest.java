package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

import static org.assertj.core.api.Assertions.assertThat;

import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.DevicePlatform;
import com.vpbank.dcp.auth.domain.enums.SessionStatus;
import com.vpbank.dcp.auth.domain.model.AdmittedSession;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import com.vpbank.dcp.auth.domain.model.EnrollmentTransaction;
import com.vpbank.dcp.auth.domain.model.SessionId;
import com.vpbank.dcp.auth.domain.model.TrustedDeviceId;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class EnrollmentTransactionHashCodecTest {
    private static final AdmittedSession TABLET = new AdmittedSession(
            new SessionId(UUID.fromString("33333333-3333-4333-8333-333333333333")), new CustomerId("90359"),
            Channel.MOBILE, new DeviceId("tablet-2"), SessionStatus.NEED_TRUSTED_DEVICE);
    private final EnrollmentTransaction newDevice = EnrollmentTransaction.keyExchange(
            new EnrollmentId(UUID.fromString("44444444-4444-4444-8444-444444444444")),
            TABLET,
            null,
            "{dev}",
            DevicePlatform.IOS,
            "{srv-pub}",
            "{srv-priv}",
            "digest",
            Instant.parse("2026-11-03T10:10:00.123Z"));

    @Test
    void roundTripsWithStringFieldsOnlyAndOptionalFieldsAbsentWhenUnset() {
        Map<String, String> fields = EnrollmentTransactionHashCodec.encode(newDevice);

        assertThat(fields).containsEntry("schemaVersion", "1").containsEntry("state", "KEY_EXCHANGE")
                .containsEntry("customerId", "90359").containsEntry("channel", "MOBILE").containsEntry("deviceId", "tablet-2")
                .containsEntry("sessionId", "33333333-3333-4333-8333-333333333333").containsEntry("verifyAttempts", "0")
                .containsEntry("expiresAtMs", "1793700600123").containsEntry("version", "0");
        assertThat(fields).doesNotContainKeys("targetDeviceId", "mfaTransactionId");
        assertThat(EnrollmentTransactionHashCodec.decode(fields)).contains(newDevice);

        EnrollmentTransaction knownDeviceAfterVerify = newDevice.toBuilder()
                .targetDeviceId(TrustedDeviceId.random())
                .build()
                .countVerifyAttempt()
                .markMfaRequired("mfa-1")
                .withVersion(2);
        Map<String, String> verifiedFields = EnrollmentTransactionHashCodec.encode(knownDeviceAfterVerify);
        assertThat(verifiedFields).containsEntry("state", "MFA_REQUIRED").containsEntry("mfaTransactionId", "mfa-1")
                .containsKey("targetDeviceId").containsEntry("verifyAttempts", "1").containsEntry("version", "2");
        assertThat(EnrollmentTransactionHashCodec.decode(verifiedFields)).contains(knownDeviceAfterVerify);
    }

    @Test
    void anythingUnexpectedDecodesToNoTransaction() {
        Map<String, String> fields = EnrollmentTransactionHashCodec.encode(newDevice);

        assertThat(EnrollmentTransactionHashCodec.decode(null)).isEmpty();
        assertThat(EnrollmentTransactionHashCodec.decode(without(fields, "serverPrivateJwk"))).isEmpty();
        assertThat(EnrollmentTransactionHashCodec.decode(without(fields, "sessionId"))).isEmpty();
        assertThat(EnrollmentTransactionHashCodec.decode(with(fields, "unexpected", "x"))).isEmpty();
        assertThat(EnrollmentTransactionHashCodec.decode(with(fields, "schemaVersion", "2"))).isEmpty();
        assertThat(EnrollmentTransactionHashCodec.decode(with(fields, "state", "COMPLETED"))).isEmpty();
        assertThat(EnrollmentTransactionHashCodec.decode(with(fields, "state", "MFA_REQUIRED"))).isEmpty(); // no MFA ID
        assertThat(EnrollmentTransactionHashCodec.decode(with(fields, "mfaTransactionId", "mfa-1"))).isEmpty(); // too early
        assertThat(EnrollmentTransactionHashCodec.decode(with(fields, "verifyAttempts", "-1"))).isEmpty();
        assertThat(EnrollmentTransactionHashCodec.decode(with(fields, "verifyAttempts", "one"))).isEmpty();
        assertThat(EnrollmentTransactionHashCodec.decode(with(fields, "expiresAtMs", "-5"))).isEmpty();
        assertThat(EnrollmentTransactionHashCodec.decode(with(fields, "channel", "FAX"))).isEmpty();
        assertThat(EnrollmentTransactionHashCodec.decode(with(fields, "deviceId", "has space"))).isEmpty();
        assertThat(EnrollmentTransactionHashCodec.decode(with(fields, "targetDeviceId", "not-a-uuid"))).isEmpty();
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
