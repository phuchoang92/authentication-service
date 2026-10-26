package com.vpbank.dcp.auth.domain.enums;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Arrays;
import org.junit.jupiter.api.Test;

/**
 * The enum names are the codes stored in MySQL ({@code @Enumerated(EnumType.STRING)}, the Valkey
 * HASH and the JSON bodies. Moving the enums between packages must not change a single name;
 * this list is the frozen contract.
 */
class DomainEnumCodesTest {

    @Test
    void storedAndWireCodesAreFrozen() {
        assertThat(names(RegistrationState.values()))
                .containsExactly("RESERVED", "USER_CREATED", "SMS_ACCEPTED", "READY", "FAILED");
        assertThat(names(SessionStatus.values()))
                .containsExactly("ACTIVE", "NEED_TRUSTED_DEVICE", "ENDED");
        assertThat(names(PasswordStatus.values()))
                .containsExactly("ACTIVE", "LOCKED", "PERMANENTLY_LOCKED");
        assertThat(names(Channel.values()))
                .containsExactly("MOBILE", "WEB");
        assertThat(names(DevicePlatform.values()))
                .containsExactly("ANDROID", "IOS");
        assertThat(names(DeviceStatus.values()))
                .containsExactly("PENDING", "ACTIVE", "SUSPENDED", "EXPIRED", "REVOKED");
        assertThat(names(TrustLevel.values()))
                .containsExactly("NONE", "TRUSTED");
        assertThat(names(EnrollmentPurpose.values()))
                .containsExactly("TRUST_DEVICE", "TRUST_DEVICE_APPROVAL");
        assertThat(names(EnrollmentState.values()))
                .containsExactly("KEY_EXCHANGE", "MFA_REQUIRED", "WAITING_APPROVAL", "WAITING_AUTHORIZATION",
                        "COMPLETED", "FAILED", "EXPIRED");
        assertThat(names(MfaFactor.values()))
                .containsExactly("FACE", "OTP");
        assertThat(names(PrimaryMode.values()))
                .containsExactly("DIRECT_PRIMARY", "FACE_CONFIRMED", "OLD_DEVICE_APPROVAL");
    }

    @Test
    void liveAndOpenPredicatesMatchTheSchemaComments() {
        assertThat(Arrays.stream(DeviceStatus.values()).filter(DeviceStatus::live))
                .containsExactly(DeviceStatus.PENDING, DeviceStatus.ACTIVE, DeviceStatus.SUSPENDED);
        assertThat(Arrays.stream(EnrollmentState.values()).filter(EnrollmentState::open))
                .containsExactly(EnrollmentState.KEY_EXCHANGE, EnrollmentState.MFA_REQUIRED,
                        EnrollmentState.WAITING_APPROVAL, EnrollmentState.WAITING_AUTHORIZATION);
        assertThat(Arrays.stream(SessionStatus.values()).filter(SessionStatus::live))
                .containsExactly(SessionStatus.ACTIVE, SessionStatus.NEED_TRUSTED_DEVICE);
        assertThat(Arrays.stream(RegistrationState.values()).filter(RegistrationState::finished))
                .containsExactly(RegistrationState.READY, RegistrationState.FAILED);
    }

    private static String[] names(Enum<?>[] values) {
        return Arrays.stream(values).map(Enum::name).toArray(String[]::new);
    }
}
