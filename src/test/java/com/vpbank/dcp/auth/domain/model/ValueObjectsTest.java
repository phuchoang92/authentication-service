package com.vpbank.dcp.auth.domain.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.SessionStatus;
import org.junit.jupiter.api.Test;

class ValueObjectsTest {

    @Test
    void acceptsTheContractFormats() {
        assertThat(new CustomerId("90359").value()).isEqualTo("90359");
        assertThat(new UserName("alice.ng_1").value()).isEqualTo("alice.ng_1");
        assertThat(new PhoneNumber("+84901234567").value()).isEqualTo("+84901234567");
        assertThat(new Email("Alice@Example.com").sameAs("alice@example.com")).isTrue();
        assertThat(new UserName("Alice").sameAs(new UserName("ALICE"))).isTrue();
    }

    @Test
    void rejectsWrongFormats() {
        assertThatThrownBy(() -> new CustomerId("with space")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new UserName("ab")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new PhoneNumber("0901234567")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new Email("not-an-email")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new CustomerId(null)).isInstanceOf(NullPointerException.class);
    }

    @Test
    void anAdmittedSessionIsLiveAndSaysWhichKindOfRouteItMayUse() {
        SessionId sessionId = SessionId.random();
        CustomerId alice = new CustomerId("90359");
        DeviceId phone = new DeviceId("phone-1");

        AdmittedSession restricted = new AdmittedSession(sessionId, alice, Channel.MOBILE, phone, SessionStatus.NEED_TRUSTED_DEVICE);
        AdmittedSession full = new AdmittedSession(sessionId, alice, Channel.MOBILE, phone, SessionStatus.ACTIVE);
        assertThat(restricted.restricted()).isTrue();
        assertThat(restricted.full()).isFalse();
        assertThat(full.full()).isTrue();
        assertThat(full.restricted()).isFalse();

        assertThatThrownBy(() -> new AdmittedSession(sessionId, alice, Channel.MOBILE, phone, SessionStatus.ENDED))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new AdmittedSession(sessionId, alice, Channel.MOBILE, null, SessionStatus.ACTIVE))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void personalDataIsNeverPrinted() {
        assertThat(new PhoneNumber("+84901234567").toString()).doesNotContain("8490");
        assertThat(new Email("a@b.co").toString()).doesNotContain("a@b");
    }
}
