package com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.common;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.vpbank.dcp.auth.domain.model.Channel;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Map;
import org.junit.jupiter.api.Test;

class DeviceIdProtectionTest {
    private static final CustomerId ALICE = new CustomerId("90359");
    private static final DeviceId PHONE = new DeviceId("dev-1");
    private final byte[] lookupKey = new byte[32];
    private final byte[] aesKey = key(7);
    private final DeviceIdProtection protection = new DeviceIdProtection(Map.of("d1", lookupKey), "d1",
            Map.of("e1", aesKey), "e1", new SecureRandom());

    @Test
    void lookupIsAStableKeyedDigestBoundToOwnerAndChannel() {
        byte[] digest = protection.lookup(ALICE, Channel.MOBILE, PHONE);
        assertThat(digest).hasSize(32);
        assertThat(protection.lookup(ALICE, Channel.MOBILE, PHONE)).isEqualTo(digest);
        // Frozen vector: HMAC-SHA256(32 zero bytes, "5:90359;6:MOBILE;5:dev-1;") — a refactor must not change stored lookups.
        assertThat(HexFormat.of().formatHex(digest))
                .isEqualTo(HexFormat.of().formatHex(DeviceIdProtectionTest.hmac(lookupKey, "5:90359;6:MOBILE;5:dev-1;")));
        assertThat(protection.lookup(new CustomerId("77777"), Channel.MOBILE, PHONE)).isNotEqualTo(digest);
        assertThat(protection.lookup(ALICE, Channel.WEB, PHONE)).isNotEqualTo(digest);
        assertThat(new DeviceIdProtection(Map.of("d1", key(1)), "d1", Map.of("e1", aesKey), "e1", new SecureRandom())
                .lookup(ALICE, Channel.MOBILE, PHONE)).isNotEqualTo(digest);
    }

    @Test
    void ciphertextOpensOnlyForTheSameOwnerAndKeyAndNeverShowsTheId() {
        byte[] sealed = protection.encrypt(ALICE, Channel.MOBILE, PHONE);
        assertThat(sealed[0]).isEqualTo((byte) 1);
        assertThat(new String(sealed, java.nio.charset.StandardCharsets.ISO_8859_1)).doesNotContain("dev-1");
        assertThat(protection.encrypt(ALICE, Channel.MOBILE, PHONE)).isNotEqualTo(sealed); // fresh nonce each time

        assertThat(protection.decrypt("e1", sealed, ALICE, Channel.MOBILE)).contains(PHONE);
        assertThat(protection.decrypt("e1", sealed, new CustomerId("77777"), Channel.MOBILE)).isEmpty();
        assertThat(protection.decrypt("e1", sealed, ALICE, Channel.WEB)).isEmpty();
        assertThat(protection.decrypt("e2", sealed, ALICE, Channel.MOBILE)).isEmpty();
        byte[] tampered = sealed.clone();
        tampered[tampered.length - 1] ^= 1;
        assertThat(protection.decrypt("e1", tampered, ALICE, Channel.MOBILE)).isEmpty();
        assertThat(protection.decrypt("e1", new byte[5], ALICE, Channel.MOBILE)).isEmpty();
    }

    @Test
    void keyRingsAreValidatedAndOldKeysStillDecrypt() {
        DeviceIdProtection rotated = new DeviceIdProtection(Map.of("d1", lookupKey, "d2", key(2)), "d2",
                Map.of("e1", aesKey, "e2", key(3)), "e2", new SecureRandom());
        byte[] old = protection.encrypt(ALICE, Channel.MOBILE, PHONE);
        assertThat(rotated.decrypt("e1", old, ALICE, Channel.MOBILE)).contains(PHONE);
        assertThat(rotated.lookup("d1", ALICE, Channel.MOBILE, PHONE)).isEqualTo(protection.lookup(ALICE, Channel.MOBILE, PHONE));
        assertThat(rotated.encryptionKeyId()).isEqualTo("e2");

        assertThatThrownBy(() -> new DeviceIdProtection(Map.of("d1", new byte[16]), "d1", Map.of("e1", aesKey), "e1",
                new SecureRandom())).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new DeviceIdProtection(Map.of("d1", lookupKey), "d9", Map.of("e1", aesKey), "e1",
                new SecureRandom())).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("d9");
    }

    private static byte[] key(int fill) {
        byte[] key = new byte[32];
        java.util.Arrays.fill(key, (byte) fill);
        return key;
    }

    private static byte[] hmac(byte[] key, String text) {
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new javax.crypto.spec.SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(text.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
