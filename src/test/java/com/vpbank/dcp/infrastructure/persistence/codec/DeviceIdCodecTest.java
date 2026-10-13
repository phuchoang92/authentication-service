package com.vpbank.dcp.infrastructure.persistence.codec;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class DeviceIdCodecTest {
    private static final UUID CUSTOMER = UUID.fromString("1dd8d5a1-6f35-4c19-b8b6-06aa1b98ed0d");
    private static final UUID OTHER_CUSTOMER = UUID.fromString("20a6f956-10dc-4429-99cf-12dff92ac4b4");
    private static final UUID BINDING = UUID.fromString("c725247c-f3f5-48ee-a374-745a9688a377");
    private static final String APP = "neo-mobile";
    private static final String INSTALLATION = "app-generated-installation-identifier-123";

    @Test
    void protectsAndRecoversOnlyUnderTheOriginalOwnerAppAndBinding() {
        DeviceIdCodec codec = codec("lookup-2", "encryption-2", true);

        ProtectedDeviceId protectedId = codec.protect(CUSTOMER, APP, BINDING, INSTALLATION);

        assertThat(codec.reveal(CUSTOMER, APP, BINDING, protectedId.encryptionKeyId(),
                protectedId.ciphertext())).isEqualTo(INSTALLATION);
        assertThat(protectedId.lookup()).isEqualTo(codec.lookupCandidates(CUSTOMER, APP,
                INSTALLATION).getFirst().digest());
        assertThat(codec.lookupCandidates(OTHER_CUSTOMER, APP, INSTALLATION).getFirst().digest())
                .isNotEqualTo(protectedId.lookup());
        assertThat(codec.lookupCandidates(CUSTOMER, "other-app", INSTALLATION).getFirst().digest())
                .isNotEqualTo(protectedId.lookup());
        assertThatThrownBy(() -> codec.reveal(OTHER_CUSTOMER, APP, BINDING,
                protectedId.encryptionKeyId(), protectedId.ciphertext()))
                .isInstanceOf(InvalidDeviceIdProtectionException.class);
        assertThatThrownBy(() -> codec.reveal(CUSTOMER, APP, UUID.randomUUID(),
                protectedId.encryptionKeyId(), protectedId.ciphertext()))
                .isInstanceOf(InvalidDeviceIdProtectionException.class);
        assertThatThrownBy(() -> codec.reveal(CUSTOMER, "other-app", BINDING,
                protectedId.encryptionKeyId(), protectedId.ciphertext()))
                .isInstanceOf(InvalidDeviceIdProtectionException.class);
    }

    @Test
    void detectsTamperingAndUsesFreshNonceForEachEnvelope() {
        DeviceIdCodec codec = codec("lookup-2", "encryption-2", false);
        ProtectedDeviceId first = codec.protect(CUSTOMER, APP, BINDING, INSTALLATION);
        ProtectedDeviceId second = codec.protect(CUSTOMER, APP, BINDING, INSTALLATION);

        assertThat(first.lookup()).isEqualTo(second.lookup());
        assertThat(first.ciphertext()).isNotEqualTo(second.ciphertext());
        byte[] changed = first.ciphertext();
        changed[changed.length - 1] ^= 1;
        assertThatThrownBy(() -> codec.reveal(CUSTOMER, APP, BINDING,
                first.encryptionKeyId(), changed))
                .isInstanceOf(InvalidDeviceIdProtectionException.class);
        assertThat(first.toString()).doesNotContain(INSTALLATION);
    }

    @Test
    void retainedKeysSupportControlledReadRotation() {
        DeviceIdCodec before = codec("lookup-1", "encryption-1", true);
        ProtectedDeviceId old = before.protect(CUSTOMER, APP, BINDING, INSTALLATION);
        DeviceIdCodec after = codec("lookup-2", "encryption-2", true);

        assertThat(after.lookupCandidates(CUSTOMER, APP, INSTALLATION))
                .anySatisfy(candidate -> {
                    assertThat(candidate.keyId()).isEqualTo(old.lookupKeyId());
                    assertThat(candidate.digest()).isEqualTo(old.lookup());
                });
        assertThat(after.reveal(CUSTOMER, APP, BINDING,
                old.encryptionKeyId(), old.ciphertext())).isEqualTo(INSTALLATION);
        assertThat(codec("lookup-2", "encryption-2", false)
                .lookupCandidates(CUSTOMER, APP, INSTALLATION))
                .noneSatisfy(candidate -> assertThat(candidate.digest()).isEqualTo(old.lookup()));
        assertThatThrownBy(() -> codec("lookup-2", "encryption-2", false)
                .reveal(CUSTOMER, APP, BINDING, old.encryptionKeyId(), old.ciphertext()))
                .isInstanceOf(InvalidDeviceIdProtectionException.class);
    }

    @Test
    void keyMaterialCannotBeMutatedThroughTheCaller() {
        byte[] key = filled(1);
        DeviceIdKeyMaterial material = new DeviceIdKeyMaterial("key-1", Map.of("key-1", key));
        key[0] = 99;
        byte[] returned = material.key("key-1");
        returned[0] = 88;

        assertThat(material.key("key-1")[0]).isEqualTo((byte) 1);
        assertThat(material.toString()).doesNotContain(Arrays.toString(key));
    }

    private static DeviceIdCodec codec(String activeLookup, String activeEncryption,
                                       boolean retainOldKeys) {
        Map<String, byte[]> lookups = new LinkedHashMap<>();
        Map<String, byte[]> encryptions = new LinkedHashMap<>();
        if (retainOldKeys || activeLookup.endsWith("1")) {
            lookups.put("lookup-1", filled(1));
        }
        lookups.put("lookup-2", filled(2));
        if (retainOldKeys || activeEncryption.endsWith("1")) {
            encryptions.put("encryption-1", filled(3));
        }
        encryptions.put("encryption-2", filled(4));
        return new DeviceIdCodec(new DeviceIdKeyMaterial(activeLookup, lookups),
                new DeviceIdKeyMaterial(activeEncryption, encryptions), new SecureRandom());
    }

    private static byte[] filled(int value) {
        byte[] bytes = new byte[32];
        Arrays.fill(bytes, (byte) value);
        return bytes;
    }
}
