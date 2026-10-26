package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

import static org.assertj.core.api.Assertions.assertThat;

import com.vpbank.dcp.auth.application.port.out.model.SessionLookup;
import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.model.OpaqueToken;
import com.vpbank.dcp.auth.domain.model.SessionId;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class SessionKeysTest {
    private static final SessionId SESSION = new SessionId(UUID.fromString("00000000-0000-4000-8000-000000000001"));
    private static final OpaqueToken TOKEN = OpaqueToken.of(Channel.MOBILE, SESSION, "A".repeat(43));
    private final SessionKeys keys = new SessionKeys();

    @Test
    void theKeyIsTheChannelAndSessionIdInClear() {
        // Frozen so a Java refactor cannot change stored keys (RK09/RK12); the BFF builds the same key.
        SessionLookup lookup = keys.lookupOf(TOKEN);
        assertThat(lookup).isEqualTo(new SessionLookup(Channel.MOBILE, SESSION));
        assertThat(keys.forLookup(lookup)).isEqualTo("session:v1:MOBILE:00000000-0000-4000-8000-000000000001");
    }

    @Test
    void theSecretPlaysNoPartInTheKey() {
        OpaqueToken otherSecret = OpaqueToken.of(Channel.MOBILE, SESSION, "B".repeat(43));
        assertThat(keys.lookupOf(otherSecret)).isEqualTo(keys.lookupOf(TOKEN));
        OpaqueToken web = OpaqueToken.of(Channel.WEB, SESSION, "A".repeat(43));
        assertThat(keys.forLookup(keys.lookupOf(web))).isEqualTo("session:v1:WEB:00000000-0000-4000-8000-000000000001");
    }
}
