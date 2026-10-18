package com.vpbank.dcp.infrastructure.adapter.out.crypto;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.vpbank.dcp.core.domain.customer.SubjectId;
import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.port.out.password.StoredDeviceKey;
import com.vpbank.dcp.core.port.out.trusteddevice.DeviceKeyMaterial;
import com.vpbank.dcp.core.port.out.trusteddevice.KeyExchange;
import com.vpbank.dcp.core.port.out.trusteddevice.KeyExchangeStart;
import com.vpbank.dcp.core.port.out.trusteddevice.ServerKeyExchange;
import com.vpbank.dcp.core.port.out.trusteddevice.WrappedServerKey;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Init sends {@code JWE(challenge → device key)} and Ksrv's public key; verify receives
 * {@code JWE(challenge → Ksrv)}. Only the holder of the device private key can produce the
 * second from the first. Both are ECDH-ES + A256GCM on P-256, like the Kenc token envelope.
 *
 * <p>Ksrv's private JWK is wrapped with AES-256-GCM. The AAD binds it to the owner, channel and
 * device key, so a wrapped key copied onto another session or device row does not decrypt.
 */
public final class ServerKeyExchangeAdapter implements ServerKeyExchange {
    static final String CHALLENGE_TYPE = "trusted-device-challenge+jwe";
    static final String RESPONSE_TYPE = "trusted-device-challenge-response+jwe";
    private static final String WRAP_LABEL = "BANK_SERVER_KEY_V1";
    private static final byte FORMAT_VERSION = 1;
    private static final int NONCE_BYTES = 12;
    private static final int TAG_BITS = 128;
    private static final int CHALLENGE_BYTES = 32;

    private final ServerKeyWrappingKeys wrappingKeys;
    private final StrictJoseJson strictJson;
    private final Sha256Digests digests;
    private final LengthPrefixedSigningInputEncoder encoding;
    private final SecureRandom random;

    public ServerKeyExchangeAdapter(ServerKeyWrappingKeys wrappingKeys, StrictJoseJson strictJson,
                                    Sha256Digests digests,
                                    LengthPrefixedSigningInputEncoder encoding,
                                    SecureRandom random) {
        this.wrappingKeys = Objects.requireNonNull(wrappingKeys);
        this.strictJson = Objects.requireNonNull(strictJson);
        this.digests = Objects.requireNonNull(digests);
        this.encoding = Objects.requireNonNull(encoding);
        this.random = Objects.requireNonNull(random);
    }

    @Override
    public KeyExchangeStart begin(DeviceKeyMaterial deviceKey, SubjectId owner, String channel) {
        Objects.requireNonNull(deviceKey);
        Objects.requireNonNull(owner);
        Objects.requireNonNull(channel);
        ECKey device;
        try {
            device = switch (deviceKey) {
                case DeviceKeyMaterial.Stored stored -> stored(stored.key());
                case DeviceKeyMaterial.Presented presented -> presented(presented.publicJwk());
            };
        } catch (InvalidCryptographicInputException failure) {
            return new KeyExchangeStart.InvalidDeviceKey();
        }
        byte[] challenge = new byte[CHALLENGE_BYTES];
        random.nextBytes(challenge);
        try {
            Digest32 deviceThumbprint = thumbprint(device);
            ECKey server = new ECKeyGenerator(Curve.P_256).keyIDFromThumbprint(true).generate();
            String challengeText = Base64.getUrlEncoder().withoutPadding().encodeToString(challenge);
            JWEObject jwe = new JWEObject(new JWEHeader.Builder(JWEAlgorithm.ECDH_ES,
                    EncryptionMethod.A256GCM).type(new JOSEObjectType(CHALLENGE_TYPE))
                    .keyID(deviceThumbprint.base64Url()).build(), new Payload(challengeText));
            jwe.encrypt(new ECDHEncrypter(device));
            KeyExchange exchange = new KeyExchange(
                    wrap(server, owner, channel, deviceThumbprint),
                    server.toPublicJWK().toJSONString(),
                    digests.sha256(challengeText.getBytes(StandardCharsets.US_ASCII)),
                    device.toPublicJWK().toJSONString(), deviceThumbprint);
            return new KeyExchangeStart.Started(exchange, jwe.serialize());
        } catch (JOSEException failure) {
            throw new InvalidCryptographicInputException(failure);
        } finally {
            Arrays.fill(challenge, (byte) 0);
        }
    }

    @Override
    public boolean answers(KeyExchange exchange, SubjectId owner, String channel, String responseJwe) {
        Objects.requireNonNull(exchange);
        Objects.requireNonNull(owner);
        Objects.requireNonNull(channel);
        if (responseJwe == null) {
            return false;
        }
        try {
            strictJson.checkCompactJweHeader(responseJwe);
            ECKey server = unwrap(exchange.serverKey(), owner, channel,
                    exchange.deviceKeyThumbprint());
            JWEObject jwe = JWEObject.parse(responseJwe);
            JWEHeader header = jwe.getHeader();
            if (!JWEAlgorithm.ECDH_ES.equals(header.getAlgorithm())
                    || !EncryptionMethod.A256GCM.equals(header.getEncryptionMethod())
                    || header.getType() == null || !RESPONSE_TYPE.equals(header.getType().toString())
                    || !server.getKeyID().equals(header.getKeyID())
                    || header.getCompressionAlgorithm() != null
                    || (header.getCriticalParams() != null && !header.getCriticalParams().isEmpty())) {
                return false;
            }
            jwe.decrypt(new ECDHDecrypter(server));
            byte[] answer = jwe.getPayload().toString().getBytes(StandardCharsets.US_ASCII);
            return MessageDigest.isEqual(digests.sha256(answer).bytes(),
                    exchange.challengeDigest().bytes());
        } catch (InvalidCryptographicInputException | ParseException | JOSEException failure) {
            return false;
        }
    }

    private ECKey presented(String publicJwk) {
        try {
            JWK parsed = JWK.parse(publicJwk);
            if (!(parsed instanceof ECKey key) || key.isPrivate()
                    || !Curve.P_256.equals(key.getCurve())) {
                throw new InvalidCryptographicInputException();
            }
            return key.toPublicJWK();
        } catch (ParseException failure) {
            throw new InvalidCryptographicInputException(failure);
        }
    }

    /** Same decoding as the password device proof: SPKI must hash to the stored thumbprint. */
    private ECKey stored(StoredDeviceKey stored) {
        try {
            var publicKey = KeyFactory.getInstance("EC")
                    .generatePublic(new X509EncodedKeySpec(stored.publicKeySpki()));
            if (!(publicKey instanceof ECPublicKey ecPublicKey)) {
                throw new InvalidCryptographicInputException();
            }
            ECKey key = new ECKey.Builder(Curve.P_256, ecPublicKey).build();
            if (!thumbprint(key).equals(stored.thumbprint())) {
                throw new InvalidCryptographicInputException();
            }
            return key;
        } catch (GeneralSecurityException | JOSEException | IllegalArgumentException failure) {
            throw new InvalidCryptographicInputException(failure);
        }
    }

    private WrappedServerKey wrap(ECKey server, SubjectId owner, String channel,
                                  Digest32 deviceThumbprint) {
        String keyId = wrappingKeys.activeKeyId();
        byte[] plain = server.toJSONString().getBytes(StandardCharsets.UTF_8);
        byte[] nonce = new byte[NONCE_BYTES];
        random.nextBytes(nonce);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(wrappingKeys.key(keyId), "AES"),
                    new GCMParameterSpec(TAG_BITS, nonce));
            cipher.updateAAD(aad(owner, channel, deviceThumbprint));
            byte[] encrypted = cipher.doFinal(plain);
            return new WrappedServerKey(keyId, ByteBuffer.allocate(1 + NONCE_BYTES + encrypted.length)
                    .put(FORMAT_VERSION).put(nonce).put(encrypted).array());
        } catch (GeneralSecurityException failure) {
            throw new InvalidCryptographicInputException(failure);
        } finally {
            Arrays.fill(plain, (byte) 0);
        }
    }

    private ECKey unwrap(WrappedServerKey wrapped, SubjectId owner, String channel,
                         Digest32 deviceThumbprint) {
        byte[] ciphertext = wrapped.ciphertext();
        if (ciphertext.length < 1 + NONCE_BYTES + 16 || ciphertext[0] != FORMAT_VERSION) {
            throw new InvalidCryptographicInputException();
        }
        byte[] plain = null;
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(wrappingKeys.key(wrapped.keyId()), "AES"),
                    new GCMParameterSpec(TAG_BITS, ciphertext, 1, NONCE_BYTES));
            cipher.updateAAD(aad(owner, channel, deviceThumbprint));
            plain = cipher.doFinal(ciphertext, 1 + NONCE_BYTES, ciphertext.length - 1 - NONCE_BYTES);
            ECKey server = ECKey.parse(new String(plain, StandardCharsets.UTF_8));
            if (!server.isPrivate() || !Curve.P_256.equals(server.getCurve())) {
                throw new InvalidCryptographicInputException();
            }
            return server;
        } catch (GeneralSecurityException | ParseException failure) {
            throw new InvalidCryptographicInputException(failure);
        } finally {
            if (plain != null) {
                Arrays.fill(plain, (byte) 0);
            }
        }
    }

    private byte[] aad(SubjectId owner, String channel, Digest32 deviceThumbprint) {
        return encoding.encode(List.of(WRAP_LABEL, owner.value().toString(), channel,
                deviceThumbprint.base64Url()));
    }

    private static Digest32 thumbprint(ECKey key) throws JOSEException {
        return Digest32.fromBytes(key.computeThumbprint().decode());
    }
}
