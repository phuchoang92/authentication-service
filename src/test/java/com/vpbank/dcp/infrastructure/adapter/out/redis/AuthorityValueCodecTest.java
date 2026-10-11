package com.vpbank.dcp.infrastructure.adapter.out.redis;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.vpbank.dcp.infrastructure.adapter.out.redis.codec.DenyCauses;
import com.vpbank.dcp.infrastructure.adapter.out.redis.codec.InvalidAuthorityValueException;
import com.vpbank.dcp.infrastructure.adapter.out.redis.codec.SecurityFloor;
import com.vpbank.dcp.infrastructure.adapter.out.redis.codec.ServingControlCodec;
import com.vpbank.dcp.infrastructure.adapter.out.redis.codec.ServingControlSnapshot;
import com.vpbank.dcp.infrastructure.adapter.out.redis.codec.ServingState;
import com.vpbank.dcp.infrastructure.adapter.out.redis.codec.SubjectGuardCodec;
import com.vpbank.dcp.infrastructure.adapter.out.redis.codec.SubjectGuardSnapshot;
import java.time.Instant;
import java.util.HashMap;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class AuthorityValueCodecTest {

    @Test
    void controlRoundTripRejectsUnknownSchemaAndFields() {
        var original = new ServingControlSnapshot(ServingState.CLOSED,
                UUID.randomUUID(), "redis-run", UUID.randomUUID(), 7,
                Instant.ofEpochMilli(1791687600000L));
        var codec = new ServingControlCodec();
        var encoded = new HashMap<Object, Object>(codec.encode(original));
        assertThat(codec.decode(encoded)).isEqualTo(original);

        encoded.put("schemaVersion", "2");
        assertThatThrownBy(() -> codec.decode(encoded))
                .isInstanceOf(InvalidAuthorityValueException.class);
        encoded.put("schemaVersion", "1");
        encoded.put("unexpected", "1");
        assertThatThrownBy(() -> codec.decode(encoded))
                .isInstanceOf(InvalidAuthorityValueException.class);
    }

    @Test
    void guardRoundTripPreservesIndependentDenialCauses() {
        var original = new SubjectGuardSnapshot(UUID.randomUUID(), UUID.randomUUID(), 12,
                new SecurityFloor(9, 6), new DenyCauses(true, true,
                Optional.of(UUID.randomUUID())));
        var codec = new SubjectGuardCodec();
        var encoded = new HashMap<Object, Object>(codec.encode(original));
        assertThat(codec.decode(encoded)).isEqualTo(original);

        encoded.put("customerDenied", "true");
        assertThatThrownBy(() -> codec.decode(encoded))
                .isInstanceOf(InvalidAuthorityValueException.class);
    }
}
