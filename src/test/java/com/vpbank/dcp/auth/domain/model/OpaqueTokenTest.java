package com.vpbank.dcp.auth.domain.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class OpaqueTokenTest {
    private static final String RANDOM = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 43 chars

    @Test
    void acceptsVersionDotFortyThreeBase64UrlChars() {
        OpaqueToken token = new OpaqueToken("k1." + RANDOM);
        assertThat(token.keyVersion()).isEqualTo("k1");
        assertThat(token.toString()).doesNotContain(RANDOM);
    }

    @Test
    void rejectsOtherShapes() {
        assertThatThrownBy(() -> new OpaqueToken("k1." + RANDOM.substring(1))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new OpaqueToken("x1." + RANDOM)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new OpaqueToken("k1." + RANDOM.replace('A', '+'))).isInstanceOf(IllegalArgumentException.class);
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
