package com.vpbank.dcp.infrastructure.adapter.out.crypto;

import com.vpbank.dcp.core.customer.SubjectId;
import com.vpbank.dcp.core.security.Digest32;
import com.vpbank.dcp.core.device.StoredDeviceKey;
import com.vpbank.dcp.core.trusteddevice.DeviceKeyMaterial;
import com.vpbank.dcp.core.session.KeyExchange;
import com.vpbank.dcp.core.trusteddevice.KeyExchangeStart;
import com.vpbank.dcp.core.trusteddevice.ServerKeyExchange;
import com.vpbank.dcp.core.session.WrappedServerKey;
import com.vpbank.dcp.hpke.ServerKeyWrapper;
import com.vpbank.dcp.hpke.XWingHpke;
import com.vpbank.dcp.hpke.XWingKeyPair;
import com.vpbank.dcp.hpke.XWingPublicKey;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * Init seals a random challenge to the device key; verify opens the proof the App sealed to Ksrv
 * and expects exactly that challenge. Only the holder of the device private key can turn the first
 * into the second. Both are HPKE X-Wing ({@link XWingHpke#SUITE}), with the enrollment ID as AAD.
 *
 * <p>Ksrv's private keys are wrapped with a KEK. The context binds it to the owner, channel and
 * device key, so a wrapped key copied onto another session or device row does not open.
 */
public final class ServerKeyExchangeAdapter implements ServerKeyExchange {
    private static final int CHALLENGE_BYTES = 32;
    /** HPKE {@code info} of each message, as the App contract fixes them (sample doc §1). */
    private static final byte[] CHALLENGE_INFO =
            "DCP/v1/trusted-device-challenge".getBytes(StandardCharsets.UTF_8);
    private static final byte[] PROOF_INFO = "DCP/v1/trusted-device-proof".getBytes(StandardCharsets.UTF_8);

    private final XWingHpke hpke;
    private final ServerKeyWrapper wrapper;
    private final Sha256Digests digests;
    private final LengthPrefixedSigningInputEncoder encoding;
    private final SecureRandom random;

    public ServerKeyExchangeAdapter(XWingHpke hpke, ServerKeyWrapper wrapper, Sha256Digests digests,
                                    LengthPrefixedSigningInputEncoder encoding,
                                    SecureRandom random) {
        this.hpke = Objects.requireNonNull(hpke);
        this.wrapper = Objects.requireNonNull(wrapper);
        this.digests = Objects.requireNonNull(digests);
        this.encoding = Objects.requireNonNull(encoding);
        this.random = Objects.requireNonNull(random);
    }

    @Override
    public KeyExchangeStart begin(DeviceKeyMaterial deviceKey, SubjectId owner, String channel) {
        Objects.requireNonNull(deviceKey);
        Objects.requireNonNull(owner);
        Objects.requireNonNull(channel);
        XWingPublicKey device;
        try {
            device = switch (deviceKey) {
                case DeviceKeyMaterial.Stored stored -> stored(stored.key());
                case DeviceKeyMaterial.Presented presented ->
                        XWingPublicKey.fromBase64Url(presented.publicKey());
            };
        } catch (InvalidKeyException failure) {
            return new KeyExchangeStart.InvalidDeviceKey();
        }
        UUID enrollmentId = UUID.randomUUID();
        Digest32 deviceThumbprint = digests.sha256(device.toBytes());
        byte[] challenge = new byte[CHALLENGE_BYTES];
        random.nextBytes(challenge);
        try (XWingKeyPair server = XWingKeyPair.generate()) {
            String protectedChallenge;
            try {
                // The JDK checks here whether ML-KEM and X25519 can use the device key.
                protectedChallenge = hpke.seal(device, CHALLENGE_INFO,
                        aad(enrollmentId), challenge);
            } catch (InvalidKeyException unusable) {
                return new KeyExchangeStart.InvalidDeviceKey();
            }
            ServerKeyWrapper.Wrapped wrapped = wrapper.wrap(server,
                    context(owner, channel, deviceThumbprint));
            KeyExchange exchange = new KeyExchange(
                    new WrappedServerKey(wrapped.keyId(), wrapped.ciphertext()),
                    server.publicKey().toBase64Url(), digests.sha256(challenge),
                    device.toBase64Url(), deviceThumbprint, enrollmentId);
            return new KeyExchangeStart.Started(exchange, XWingHpke.SUITE, protectedChallenge);
        } finally {
            Arrays.fill(challenge, (byte) 0);
        }
    }

    @Override
    public boolean answers(KeyExchange exchange, SubjectId owner, String channel,
                           String keyExchangeProof) {
        Objects.requireNonNull(exchange);
        Objects.requireNonNull(owner);
        Objects.requireNonNull(channel);
        if (keyExchangeProof == null) {
            return false;
        }
        byte[] answer = null;
        WrappedServerKey stored = exchange.serverKey();
        try (XWingKeyPair server = wrapper.unwrap(
                new ServerKeyWrapper.Wrapped(stored.keyId(), stored.ciphertext()),
                context(owner, channel, exchange.deviceKeyThumbprint()))) {
            answer = hpke.open(server, PROOF_INFO,
                    aad(exchange.enrollmentId()), keyExchangeProof);
            return answer.length == CHALLENGE_BYTES && MessageDigest.isEqual(
                    digests.sha256(answer).bytes(), exchange.challengeDigest().bytes());
        } catch (GeneralSecurityException failure) {
            return false;
        } finally {
            if (answer != null) {
                Arrays.fill(answer, (byte) 0);
            }
        }
    }

    /** A known device keeps its raw public key; it must hash to the stored thumbprint. */
    private XWingPublicKey stored(StoredDeviceKey stored) throws InvalidKeyException {
        XWingPublicKey key = XWingPublicKey.fromBytes(stored.publicKeySpki());
        if (!digests.sha256(key.toBytes()).equals(stored.thumbprint())) {
            throw new InvalidKeyException("stored device key does not match its thumbprint");
        }
        return key;
    }

    private byte[] context(SubjectId owner, String channel, Digest32 deviceThumbprint) {
        return encoding.encode(List.of(owner.value().toString(), channel,
                deviceThumbprint.base64Url()));
    }

    /** The App receives the enrollment ID as text and uses its UTF-8 bytes. */
    private static byte[] aad(UUID enrollmentId) {
        return enrollmentId.toString().getBytes(StandardCharsets.UTF_8);
    }
}
