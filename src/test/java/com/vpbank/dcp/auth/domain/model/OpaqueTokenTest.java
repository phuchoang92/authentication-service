package com.vpbank.dcp.auth.domain.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.vpbank.dcp.auth.domain.enums.Channel;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class OpaqueTokenTest {
    private static final String SECRET = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 43 chars
    private static final SessionId SESSION = new SessionId(UUID.fromString("00000000-0000-4000-8000-000000000001"));

    @Test
    void carriesChannelAndSessionIdInClearAndKeepsTheSecretOutOfLogs() {
        OpaqueToken token = OpaqueToken.of(Channel.MOBILE, SESSION, SECRET);
        assertThat(token.value()).isEqualTo("s1:auth:session:MOBILE:00000000-0000-4000-8000-000000000001:" + SECRET);
        assertThat(token.channel()).isEqualTo(Channel.MOBILE);
        assertThat(token.sessionId()).isEqualTo(SESSION);
        assertThat(token.secret()).isEqualTo(SECRET);
        assertThat(token.toString()).doesNotContain(SECRET).contains("00000000-0000-4000-8000-000000000001");
        assertThat(new OpaqueToken(token.value())).isEqualTo(token);
    }

    @Test
    void rejectsOtherShapes() {
        String prefix = "s1:auth:session:MOBILE:00000000-0000-4000-8000-000000000001:";
        assertThatThrownBy(() -> new OpaqueToken(prefix + SECRET.substring(1))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new OpaqueToken(prefix + SECRET.replace('A', '+'))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new OpaqueToken("s2:auth:session:MOBILE:00000000-0000-4000-8000-000000000001:" + SECRET))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new OpaqueToken("s1:auth:session:FAX:00000000-0000-4000-8000-000000000001:" + SECRET))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new OpaqueToken("s1:auth:session:MOBILE:not-a-uuid:" + SECRET))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new OpaqueToken("k1." + SECRET)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new Password(new char[0])).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void passwordIsRedactedAndClearable() {
        Password password = new Password("Secret123".toCharArray());
        assertThat(password.toString()).doesNotContain("Secret");
        password.clear();
        assertThat(password.value()).containsOnly('\0');
    }
}
