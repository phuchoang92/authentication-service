package com.vpbank.dcp.infrastructure.adapter.out.totp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class TotpSecretCodecTest {
    private final TotpSecretCodec codec = new TotpSecretCodec(
            new TotpSecretKeys("test", Map.of("test", new byte[32])), new SecureRandom());

    @Test
    void bindsCiphertextToCustomerChannelDeviceAndCredential() {
        UUID customer = UUID.randomUUID();
        UUID device = UUID.randomUUID();
        UUID credential = UUID.randomUUID();
        byte[] secret = "12345678901234567890".getBytes(StandardCharsets.US_ASCII);
        ProtectedTotpSecret protectedSecret = codec.protect(customer, "neo-mobile", device,
                credential, secret);

        assertThat(codec.reveal(customer, "neo-mobile", device, credential, protectedSecret))
                .isEqualTo(secret);
        assertThatThrownBy(() -> codec.reveal(UUID.randomUUID(), "neo-mobile", device,
                credential, protectedSecret)).isInstanceOf(InvalidTotpSecretException.class);
        assertThatThrownBy(() -> codec.reveal(customer, "other-channel", device,
                credential, protectedSecret)).isInstanceOf(InvalidTotpSecretException.class);
        assertThatThrownBy(() -> codec.reveal(customer, "neo-mobile", UUID.randomUUID(),
                credential, protectedSecret)).isInstanceOf(InvalidTotpSecretException.class);
        assertThatThrownBy(() -> codec.reveal(customer, "neo-mobile", device,
                UUID.randomUUID(), protectedSecret)).isInstanceOf(InvalidTotpSecretException.class);
        assertThat(protectedSecret.toString()).doesNotContain("12345678901234567890");
    }
}
