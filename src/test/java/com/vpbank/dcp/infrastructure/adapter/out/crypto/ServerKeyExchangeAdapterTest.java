package com.vpbank.dcp.infrastructure.adapter.out.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.vpbank.dcp.core.customer.SubjectId;
import com.vpbank.dcp.core.security.Digest32;
import com.vpbank.dcp.core.device.StoredDeviceKey;
import com.vpbank.dcp.core.trusteddevice.DeviceKeyMaterial;
import com.vpbank.dcp.core.session.KeyExchange;
import com.vpbank.dcp.core.trusteddevice.KeyExchangeStart;
import com.vpbank.dcp.core.session.WrappedServerKey;
import com.vpbank.dcp.hpke.ServerKeyWrapper;
import com.vpbank.dcp.hpke.XWingHpke;
import com.vpbank.dcp.hpke.XWingKeyPair;
import com.vpbank.dcp.hpke.XWingPublicKey;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import javax.crypto.AEADBadTagException;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

class ServerKeyExchangeAdapterTest {
    private static final String CHANNEL = "neo-mobile";
    /** The App contract's values, written out here so a change in the adapter is caught. */
    private static final byte[] CHALLENGE_INFO =
            "DCP/v1/trusted-device-challenge".getBytes(StandardCharsets.UTF_8);
    private static final byte[] PROOF_INFO = "DCP/v1/trusted-device-proof".getBytes(StandardCharsets.UTF_8);
    private final SecureRandom random = new SecureRandom();
    private final SubjectId owner = new SubjectId(UUID.randomUUID());
    private final Sha256Digests digests = new Sha256Digests();
    private final XWingHpke hpke = new XWingHpke();
    private final ServerKeyWrapper wrapper = wrapper("w1");
    private final ServerKeyExchangeAdapter exchange = new ServerKeyExchangeAdapter(hpke, wrapper,
            digests, new LengthPrefixedSigningInputEncoder(), random);
    private final XWingKeyPair device = XWingKeyPair.generate();

    @Test
    void holderOfTheDeviceKeyAnswersTheChallenge() throws Exception {
        KeyExchangeStart.Started started = startedWith(presented(device));

        assertThat(started.suite()).isEqualTo("DCP-HPKE-XWING-SHA256-AES256GCM-V1");
        assertThat(started.exchange().deviceKeyThumbprint())
                .isEqualTo(digests.sha256(device.publicKey().toBytes()));
        assertThat(started.exchange().devicePublicKey()).isEqualTo(device.publicKey().toBase64Url());
        assertThat(exchange.answers(started.exchange(), owner, CHANNEL, appAnswer(started, device)))
                .isTrue();
    }

    /** The App side of the contract as CryptoKit runs it: aad is the UTF-8 enrollment ID. */
    @Test
    void cryptoKitProofIsAccepted() throws Exception {
        JsonNode vector = cryptoKitVector();
        UUID enrollmentId = UUID.fromString(vector.get("enrollmentId").asString());
        Digest32 deviceThumbprint = digests.sha256(device.publicKey().toBytes());
        WrappedServerKey serverKey;
        try (XWingKeyPair ksrv = XWingKeyPair.fromStorage(b64(vector, "recipientStorage"))) {
            assertThat(ksrv.publicKey().toBase64Url())
                    .isEqualTo(vector.get("recipientPublicKey").asString());
            ServerKeyWrapper.Wrapped wrapped = wrapper.wrap(ksrv,
                    new LengthPrefixedSigningInputEncoder().encode(List.of(owner.value().toString(),
                            CHANNEL, deviceThumbprint.base64Url())));
            serverKey = new WrappedServerKey(wrapped.keyId(), wrapped.ciphertext());
        }
        KeyExchange stored = new KeyExchange(serverKey, vector.get("recipientPublicKey").asString(),
                digests.sha256(b64(vector, "plaintext")), device.publicKey().toBase64Url(),
                deviceThumbprint, enrollmentId);
        String proof = vector.get("envelope").asString();

        assertThat(exchange.answers(stored, owner, CHANNEL, proof)).isTrue();
        KeyExchange otherEnrollment = new KeyExchange(serverKey, stored.serverPublicKey(),
                stored.challengeDigest(), stored.devicePublicKey(), deviceThumbprint, UUID.randomUUID());
        assertThat(exchange.answers(otherEnrollment, owner, CHANNEL, proof)).isFalse();
    }

    /**
     * Seals a challenge to a CryptoKit-made device key and writes it in the DCP vector format, with
     * the challenge's SHA-256 (all Auth keeps), so CryptoKit can be shown to open it:
     * {@code vector-check target/auth-trusted-device-challenge.json}.
     */
    @Test
    void sealedChallengeIsWrittenForTheCryptoKitCheck() throws Exception {
        JsonNode cryptoKitDevice = null;
        try (InputStream in = getClass().getResourceAsStream(
                "/dcp-hpke-xwing/vectors/dcp-hpke-xwing-v1-from-cryptokit.json")) {
            for (JsonNode v : new JsonMapper().readTree(in).get("vectors")) {
                if (v.get("name").asString().equals("trusted-device-challenge")) {
                    cryptoKitDevice = v;
                }
            }
        }
        String devicePublicKey = cryptoKitDevice.get("recipientPublicKey").asString();
        KeyExchangeStart.Started started = startedWith(new DeviceKeyMaterial.Presented(devicePublicKey));
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        Map<String, String> vector = Map.of("name", "auth-trusted-device-challenge",
                "suite", started.suite(), "info", "DCP/v1/trusted-device-challenge",
                "recipientSeed", cryptoKitDevice.get("recipientSeed").asString(),
                "recipientPublicKey", devicePublicKey, "aad", b64.encodeToString(aad(started)),
                "plaintextSha256", started.exchange().challengeDigest().base64Url(),
                "envelope", started.protectedChallenge());

        Files.writeString(Path.of("target", "auth-trusted-device-challenge.json"),
                new JsonMapper().writeValueAsString(Map.of("source",
                        "authentication-service ServerKeyExchangeAdapter (dcp-hpke-xwing on JDK 25)",
                        "vectors", List.of(vector))));
    }

    /** A known device is challenged with the key stored at trust time, not one it sends now. */
    @Test
    void storedKeyIsUsedWhenItMatchesItsThumbprint() throws Exception {
        byte[] raw = device.publicKey().toBytes();
        KeyExchangeStart.Started started = startedWith(
                new DeviceKeyMaterial.Stored(new StoredDeviceKey(raw, digests.sha256(raw))));

        assertThat(exchange.answers(started.exchange(), owner, CHANNEL, appAnswer(started, device)))
                .isTrue();
    }

    /** Devices trusted with an ES256 key cannot be challenged any more: they must trust again. */
    @Test
    void storedKeyThatIsMismatchedOrNotXWingIsRefused() throws Exception {
        byte[] raw = device.publicKey().toBytes();
        byte[] otherRaw = XWingKeyPair.generate().publicKey().toBytes();
        assertThat(exchange.begin(new DeviceKeyMaterial.Stored(
                new StoredDeviceKey(raw, digests.sha256(otherRaw))), owner, CHANNEL))
                .isInstanceOf(KeyExchangeStart.InvalidDeviceKey.class);

        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");
        ec.initialize(new ECGenParameterSpec("secp256r1"));
        byte[] es256 = ec.generateKeyPair().getPublic().getEncoded();
        assertThat(exchange.begin(new DeviceKeyMaterial.Stored(
                new StoredDeviceKey(es256, digests.sha256(es256))), owner, CHANNEL))
                .isInstanceOf(KeyExchangeStart.InvalidDeviceKey.class);
    }

    @Test
    void presentedKeyThatIsNotAnXWingPublicKeyIsRefused() {
        String key = device.publicKey().toBase64Url();
        byte[] outOfRange = new byte[1216];
        java.util.Arrays.fill(outOfRange, (byte) 0xff);
        for (String bad : List.of(key.substring(1), key + "A", key.replace('A', '+'),
                Base64.getUrlEncoder().withoutPadding().encodeToString(outOfRange),
                "{\"kty\":\"EC\",\"crv\":\"P-256\"}")) {
            assertThat(exchange.begin(new DeviceKeyMaterial.Presented(bad), owner, CHANNEL))
                    .isInstanceOf(KeyExchangeStart.InvalidDeviceKey.class);
        }
    }

    /** Without the device private key the challenge cannot be read, so it cannot be answered. */
    @Test
    void anotherDeviceCannotReadTheChallenge() {
        KeyExchangeStart.Started started = startedWith(presented(device));
        XWingKeyPair thief = XWingKeyPair.generate();

        assertThatThrownBy(() -> hpke.open(thief, CHALLENGE_INFO,
                aad(started), started.protectedChallenge()))
                .isInstanceOf(AEADBadTagException.class);
    }

    @Test
    void wrongProofIsFalseNeverAnException() throws Exception {
        KeyExchangeStart.Started started = startedWith(presented(device));
        KeyExchange stored = started.exchange();
        XWingPublicKey server = XWingPublicKey.fromBase64Url(stored.serverPublicKey());
        byte[] challenge = readChallenge(started, device);
        byte[] otherAad = UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8);

        for (String proof : List.of(
                hpke.seal(server, PROOF_INFO, aad(started), new byte[32]),
                hpke.seal(server, CHALLENGE_INFO, aad(started), challenge),
                hpke.seal(server, PROOF_INFO, otherAad, challenge),
                hpke.seal(device.publicKey(), PROOF_INFO, aad(started),
                        challenge),
                started.protectedChallenge(), "garbage", "")) {
            assertThat(exchange.answers(stored, owner, CHANNEL, proof)).isFalse();
        }
        assertThat(exchange.answers(stored, owner, CHANNEL, null)).isFalse();
    }

    /** A proof answers only its own exchange, even for the same device. */
    @Test
    void proofOfAnotherExchangeIsFalse() throws Exception {
        KeyExchangeStart.Started first = startedWith(presented(device));
        KeyExchangeStart.Started second = startedWith(presented(device));

        assertThat(first.exchange().enrollmentId()).isNotEqualTo(second.exchange().enrollmentId());
        assertThat(exchange.answers(second.exchange(), owner, CHANNEL, appAnswer(first, device)))
                .isFalse();
    }

    /** The wrapped Ksrv only unwraps for the owner, channel and device it was created for. */
    @Test
    void wrappedServerKeyIsBoundToOwnerChannelAndDevice() throws Exception {
        KeyExchangeStart.Started started = startedWith(presented(device));
        KeyExchange stored = started.exchange();
        String answer = appAnswer(started, device);
        KeyExchange otherDevice = new KeyExchange(stored.serverKey(), stored.serverPublicKey(),
                stored.challengeDigest(), stored.devicePublicKey(),
                Digest32.fromBytes(new byte[32]), stored.enrollmentId());

        assertThat(exchange.answers(stored, new SubjectId(UUID.randomUUID()), CHANNEL, answer)).isFalse();
        assertThat(exchange.answers(stored, owner, "other-channel", answer)).isFalse();
        assertThat(exchange.answers(otherDevice, owner, CHANNEL, answer)).isFalse();
    }

    /** Only the KEK-wrapped Ksrv is stored; it must fit the V20 column. */
    @Test
    void onlyTheWrappedServerKeyIsStored() {
        WrappedServerKey stored = startedWith(presented(device)).exchange().serverKey();

        assertThat(stored.keyId()).isEqualTo("w1");
        assertThat(stored.ciphertext()[0]).isEqualTo((byte) 0x03);
        assertThat(stored.ciphertext().length).isLessThanOrEqualTo(4096);
    }

    @Test
    void unknownWrappingKeyIdDenies() throws Exception {
        KeyExchangeStart.Started started = startedWith(presented(device));
        ServerKeyExchangeAdapter rotatedAway = new ServerKeyExchangeAdapter(hpke, wrapper("w2"),
                digests, new LengthPrefixedSigningInputEncoder(), random);

        assertThat(rotatedAway.answers(started.exchange(), owner, CHANNEL,
                appAnswer(started, device))).isFalse();
    }

    private KeyExchangeStart.Started startedWith(DeviceKeyMaterial key) {
        KeyExchangeStart start = exchange.begin(key, owner, CHANNEL);
        assertThat(start).isInstanceOf(KeyExchangeStart.Started.class);
        return (KeyExchangeStart.Started) start;
    }

    private static DeviceKeyMaterial presented(XWingKeyPair key) {
        return new DeviceKeyMaterial.Presented(key.publicKey().toBase64Url());
    }

    private static byte[] aad(KeyExchangeStart.Started started) {
        return started.exchange().enrollmentId().toString().getBytes(StandardCharsets.UTF_8);
    }

    private byte[] readChallenge(KeyExchangeStart.Started started, XWingKeyPair deviceKey)
            throws Exception {
        return hpke.open(deviceKey, CHALLENGE_INFO, aad(started),
                started.protectedChallenge());
    }

    /** What the App does: open with the device key, seal the same bytes to Ksrv. */
    private String appAnswer(KeyExchangeStart.Started started, XWingKeyPair deviceKey)
            throws Exception {
        return hpke.seal(XWingPublicKey.fromBase64Url(started.exchange().serverPublicKey()),
                PROOF_INFO, aad(started),
                readChallenge(started, deviceKey));
    }

    private ServerKeyWrapper wrapper(String keyId) {
        return new ServerKeyWrapper(keyId, Map.of(keyId, new byte[32]));
    }

    private static JsonNode cryptoKitVector() throws Exception {
        try (InputStream in = ServerKeyExchangeAdapterTest.class.getResourceAsStream(
                "/trusted-device/cryptokit-trusted-device-proof.json")) {
            return new JsonMapper().readTree(in).get("vectors").get(0);
        }
    }

    private static byte[] b64(JsonNode node, String field) {
        return Base64.getUrlDecoder().decode(node.get(field).asString());
    }
}
