package com.vpbank.dcp.auth.domain.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.vpbank.dcp.auth.domain.exception.RegistrationStateException;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class RegistrationTest {
    private final Registration reserved = Registration.reserve(RegistrationId.random(), new CustomerId("90359"),
            new UserName("alice"), new RequestDigest(new byte[32]), Instant.parse("2026-10-26T00:00:00Z"));

    @Test
    void walksTheStepsInOrderKeepingTheExpectedVersion() {
        Registration userCreated = reserved.markUserCreated("iss", "sub-1");
        Registration smsAccepted = userCreated.withVersion(1).markSmsAccepted();
        Registration ready = smsAccepted.withVersion(2).complete();

        assertThat(reserved.state()).isEqualTo(RegistrationState.RESERVED);
        assertThat(userCreated.state()).isEqualTo(RegistrationState.USER_CREATED);
        assertThat(userCreated.version()).isZero();
        assertThat(userCreated.identitySubject()).isEqualTo("sub-1");
        assertThat(smsAccepted.state()).isEqualTo(RegistrationState.SMS_ACCEPTED);
        assertThat(ready.state()).isEqualTo(RegistrationState.READY);
        assertThat(ready.version()).isEqualTo(2);
        assertThat(ready.isOpen()).isFalse();
    }

    @Test
    void stepsOutOfOrderAreProgrammingErrors() {
        assertThatThrownBy(reserved::markSmsAccepted).isInstanceOf(RegistrationStateException.class)
                .hasMessageContaining("RESERVED").hasMessageContaining("USER_CREATED");
        assertThatThrownBy(reserved::complete).isInstanceOf(RegistrationStateException.class);
        assertThatThrownBy(() -> reserved.markUserCreated("iss", "sub").markUserCreated("iss", "sub"))
                .isInstanceOf(RegistrationStateException.class);
    }

    @Test
    void anyOpenStepCanFailButFinishedOnesCannot() {
        assertThat(reserved.fail().state()).isEqualTo(RegistrationState.FAILED);
        assertThat(reserved.markUserCreated("iss", "sub").fail().state()).isEqualTo(RegistrationState.FAILED);
        assertThatThrownBy(() -> reserved.fail().fail()).isInstanceOf(RegistrationStateException.class);
        assertThatThrownBy(() -> reserved.markUserCreated("iss", "sub").markSmsAccepted().complete().fail())
                .isInstanceOf(RegistrationStateException.class);
    }

    @Test
    void identityFieldsComeTogetherAndAreRequiredFromUserCreatedOn() {
        assertThatThrownBy(() -> reserved.toBuilder().identityIssuer("iss").build())
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> reserved.toBuilder().state(RegistrationState.USER_CREATED).build())
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void sameRequestMeansSameDigest() {
        byte[] other = new byte[32];
        other[0] = 1;
        assertThat(reserved.isSameRequest(new RequestDigest(new byte[32]))).isTrue();
        assertThat(reserved.isSameRequest(new RequestDigest(other))).isFalse();
    }
}
