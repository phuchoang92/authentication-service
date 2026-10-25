package com.vpbank.dcp.auth.adapter.out.valkey;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.vpbank.dcp.auth.application.port.out.SessionLookup;
import com.vpbank.dcp.auth.domain.model.OpaqueToken;
import java.util.Map;
import org.junit.jupiter.api.Test;

class SessionKeysTest {
    private static final OpaqueToken TOKEN = new OpaqueToken("k1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    private final SessionKeys keys = new SessionKeys(Map.of("k1", new byte[32]));

    @Test
    void stableVectorForTheSessionKey() {
        // HMAC-SHA256(32 zero bytes, "k1.AAAA…A") — frozen so a Java refactor cannot change stored keys (RK09/RK12).
        SessionLookup lookup = keys.lookupOf(TOKEN);
        assertThat(lookup.keyVersion()).isEqualTo("k1");
        assertThat(lookup.digest()).hasSize(43).matches("[A-Za-z0-9_-]{43}");
        assertThat(keys.forLookup(lookup)).isEqualTo("session:v1:k1:" + lookup.digest());
        assertThat(keys.lookupOf(TOKEN)).isEqualTo(lookup);
        assertThat(lookup.digest()).isEqualTo("vrzw0wx0AiBgprejHjmoYRxx0u50kQynY0mM4x4Ofkc");
    }

    @Test
    void anotherKeyOrTokenGivesAnotherDigestAndUnknownVersionsAreRefused() {
        byte[] other = new byte[32];
        other[0] = 1;
        assertThat(new SessionKeys(Map.of("k1", other)).lookupOf(TOKEN)).isNotEqualTo(keys.lookupOf(TOKEN));
        assertThat(keys.lookupOf(new OpaqueToken("k1.BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")))
                .isNotEqualTo(keys.lookupOf(TOKEN));
        assertThatThrownBy(() -> keys.lookupOf(new OpaqueToken("k2.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new SessionKeys(Map.of("k1", new byte[16]))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new SessionLookup("k1", "short")).isInstanceOf(IllegalArgumentException.class);
    }
}
