package com.vpbank.dcp.infrastructure.adapter.out.crypto;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.vpbank.dcp.core.domain.customer.SubjectId;
import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.port.out.password.StoredDeviceKey;
import com.vpbank.dcp.core.port.out.trusteddevice.DeviceKeyMaterial;
import com.vpbank.dcp.core.port.out.trusteddevice.KeyExchangeStart;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class ServerKeyExchangeAdapterTest {
    private final SubjectId owner = new SubjectId(UUID.randomUUID());
    private final ServerKeyExchangeAdapter exchange = new ServerKeyExchangeAdapter(
            new ServerKeyWrappingKeys("w1", Map.of("w1", new byte[32])), new StrictJoseJson(),
            new Sha256Digests(), new LengthPrefixedSigningInputEncoder(), new SecureRandom());
    private final ECKey device;

    ServerKeyExchangeAdapterTest() throws Exception {
        device = new ECKeyGenerator(Curve.P_256).generate();
    }

    @Test
    void holderOfTheDeviceKeyAnswersTheChallenge() throws Exception {
        KeyExchangeStart.Started started = startedWith(presented(device));

        String answer = answer(started, device, ServerKeyExchangeAdapter.RESPONSE_TYPE);

        assertThat(exchange.answers(started.exchange(), owner, "neo-mobile", answer)).isTrue();
        assertThat(started.exchange().deviceKeyThumbprint()).isEqualTo(thumbprint(device));
    }

    /** A known device is challenged with the key stored at trust time, not one it sends now. */
    @Test
    void storedKeyIsUsedWhenItMatchesItsThumbprint() throws Exception {
        StoredDeviceKey stored = new StoredDeviceKey(device.toECPublicKey().getEncoded(),
                thumbprint(device));
        KeyExchangeStart.Started started = startedWith(new DeviceKeyMaterial.Stored(stored));

        assertThat(exchange.answers(started.exchange(), owner, "neo-mobile",
                answer(started, device, ServerKeyExchangeAdapter.RESPONSE_TYPE))).isTrue();
    }

    @Test
    void storedKeyWhoseThumbprintDoesNotMatchIsRefused() throws Exception {
        ECKey other = new ECKeyGenerator(Curve.P_256).generate();
        StoredDeviceKey mismatched = new StoredDeviceKey(device.toECPublicKey().getEncoded(),
                thumbprint(other));

        assertThat(exchange.begin(new DeviceKeyMaterial.Stored(mismatched), owner, "neo-mobile"))
                .isInstanceOf(KeyExchangeStart.InvalidDeviceKey.class);
    }

    @Test
    void privateOrNonP256PresentedKeyIsRefused() throws Exception {
        assertThat(exchange.begin(new DeviceKeyMaterial.Presented(device.toJSONString()), owner,
                "neo-mobile")).isInstanceOf(KeyExchangeStart.InvalidDeviceKey.class);
        ECKey p384 = new ECKeyGenerator(Curve.P_384).generate();
        assertThat(exchange.begin(presented(p384), owner, "neo-mobile"))
                .isInstanceOf(KeyExchangeStart.InvalidDeviceKey.class);
        assertThat(exchange.begin(new DeviceKeyMaterial.Presented("{not-json"), owner, "neo-mobile"))
                .isInstanceOf(KeyExchangeStart.InvalidDeviceKey.class);
    }

    /** Without the device private key the challenge cannot be read, so it cannot be answered. */
    @Test
    void anotherDeviceCannotReadTheChallenge() throws Exception {
        KeyExchangeStart.Started started = startedWith(presented(device));
        ECKey thief = new ECKeyGenerator(Curve.P_256).generate();
        JWEObject challenge = JWEObject.parse(started.challengeJwe());

        org.assertj.core.api.Assertions.assertThatThrownBy(
                () -> challenge.decrypt(new ECDHDecrypter(thief))).isInstanceOf(Exception.class);
    }

    @Test
    void wrongAnswerOrWrongTypeOrWrongRecipientIsFalse() throws Exception {
        KeyExchangeStart.Started started = startedWith(presented(device));
        ECKey server = ECKey.parse(started.exchange().serverPublicJwk());

        assertThat(exchange.answers(started.exchange(), owner, "neo-mobile",
                encrypt("not-the-challenge", server, ServerKeyExchangeAdapter.RESPONSE_TYPE)))
                .isFalse();
        assertThat(exchange.answers(started.exchange(), owner, "neo-mobile",
                answer(started, device, ServerKeyExchangeAdapter.CHALLENGE_TYPE))).isFalse();
        String toDevice = encrypt(readChallenge(started, device), device,
                ServerKeyExchangeAdapter.RESPONSE_TYPE);
        assertThat(exchange.answers(started.exchange(), owner, "neo-mobile", toDevice)).isFalse();
        assertThat(exchange.answers(started.exchange(), owner, "neo-mobile", "garbage")).isFalse();
        assertThat(exchange.answers(started.exchange(), owner, "neo-mobile", null)).isFalse();
    }

    /** The wrapped Ksrv only unwraps for the owner and channel it was created for. */
    @Test
    void wrappedServerKeyIsBoundToOwnerAndChannel() throws Exception {
        KeyExchangeStart.Started started = startedWith(presented(device));
        String answer = answer(started, device, ServerKeyExchangeAdapter.RESPONSE_TYPE);

        assertThat(exchange.answers(started.exchange(), new SubjectId(UUID.randomUUID()),
                "neo-mobile", answer)).isFalse();
        assertThat(exchange.answers(started.exchange(), owner, "other-channel", answer)).isFalse();
    }

    @Test
    void wrappedServerKeyDoesNotContainThePrivateScalar() throws Exception {
        KeyExchangeStart.Started started = startedWith(presented(device));
        String wrapped = new String(started.exchange().serverKey().ciphertext(),
                StandardCharsets.ISO_8859_1);

        assertThat(wrapped).doesNotContain("\"d\"").doesNotContain("\"kty\"");
        assertThat(started.exchange().serverPublicJwk()).doesNotContain("\"d\"");
    }

    @Test
    void unknownWrappingKeyIdDenies() throws Exception {
        KeyExchangeStart.Started started = startedWith(presented(device));
        ServerKeyExchangeAdapter rotatedAway = new ServerKeyExchangeAdapter(
                new ServerKeyWrappingKeys("w2", Map.of("w2", new byte[32])), new StrictJoseJson(),
                new Sha256Digests(), new LengthPrefixedSigningInputEncoder(), new SecureRandom());

        assertThat(rotatedAway.answers(started.exchange(), owner, "neo-mobile",
                answer(started, device, ServerKeyExchangeAdapter.RESPONSE_TYPE))).isFalse();
    }

    private KeyExchangeStart.Started startedWith(DeviceKeyMaterial key) {
        KeyExchangeStart start = exchange.begin(key, owner, "neo-mobile");
        assertThat(start).isInstanceOf(KeyExchangeStart.Started.class);
        return (KeyExchangeStart.Started) start;
    }

    private static DeviceKeyMaterial presented(ECKey key) {
        return new DeviceKeyMaterial.Presented(key.toPublicJWK().toJSONString());
    }

    private static String readChallenge(KeyExchangeStart.Started started, ECKey deviceKey)
            throws Exception {
        JWEObject challenge = JWEObject.parse(started.challengeJwe());
        assertThat(challenge.getHeader().getType().toString())
                .isEqualTo(ServerKeyExchangeAdapter.CHALLENGE_TYPE);
        challenge.decrypt(new ECDHDecrypter(deviceKey));
        return challenge.getPayload().toString();
    }

    /** What the App does: decrypt with the device key, re-encrypt to Ksrv. */
    private static String answer(KeyExchangeStart.Started started, ECKey deviceKey, String type)
            throws Exception {
        return encrypt(readChallenge(started, deviceKey),
                ECKey.parse(started.exchange().serverPublicJwk()), type);
    }

    private static String encrypt(String payload, ECKey recipient, String type) throws Exception {
        JWEObject jwe = new JWEObject(new JWEHeader.Builder(JWEAlgorithm.ECDH_ES,
                EncryptionMethod.A256GCM).type(new JOSEObjectType(type))
                .keyID(recipient.getKeyID() == null ? recipient.computeThumbprint().toString()
                        : recipient.getKeyID()).build(), new Payload(payload));
        jwe.encrypt(new ECDHEncrypter(recipient.toPublicJWK()));
        return jwe.serialize();
    }

    private static Digest32 thumbprint(ECKey key) throws Exception {
        return Digest32.fromBytes(key.computeThumbprint().decode());
    }
}
