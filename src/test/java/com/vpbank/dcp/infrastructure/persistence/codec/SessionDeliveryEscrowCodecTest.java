package com.vpbank.dcp.infrastructure.persistence.codec;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.vpbank.dcp.core.security.Digest32;
import com.vpbank.dcp.infrastructure.persistence.repository.InvalidSessionPersistenceException;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

class SessionDeliveryEscrowCodecTest {
    private final SessionDeliveryEscrowCodec codec =
            new SessionDeliveryEscrowCodec(JsonMapper.builder().build());

    @Test
    void preservesExistingJsonBytesAndDigestAcrossRoundTrip() {
        var delivery = new EscrowedSessionDelivery("encrypted-token", "signed-receipt", "nonce");
        byte[] expected = """
                {"tokenEnvelope":"encrypted-token","receipt":"signed-receipt","dpopNonce":"nonce"}\
                """.getBytes(StandardCharsets.UTF_8);
        Digest32 digest = Digest32.fromBytes(HexFormat.of().parseHex("467c8552389be89773120e9f9e699dde39be3b9e23dbeb9fe924fe3135ac8bd1"));
        assertThat(codec.encode(delivery)).isEqualTo(expected);
        assertThat(codec.digest(expected)).isEqualTo(digest);
        assertThat(codec.decode(expected, digest)).isEqualTo(delivery);
    }

    @Test
    void rejectsChangedBytesAndNullEscrowBeforeDeserialization() {
        byte[] bytes = codec.encode(new EscrowedSessionDelivery("ciphertext", "receipt", "nonce"));
        Digest32 original = codec.digest(bytes);
        bytes[bytes.length - 2] ^= 1;
        assertThatThrownBy(() -> codec.decode(bytes, original))
                .isInstanceOf(InvalidSessionPersistenceException.class);
        assertThatThrownBy(() -> codec.decode(null, original))
                .isInstanceOf(InvalidSessionPersistenceException.class);
    }
}
