package com.vpbank.dcp.auth.infrastructure.adapter.out.jose;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.vpbank.dcp.auth.application.port.out.gateway.DeviceProofVerifier.Outcome;
import com.vpbank.dcp.auth.application.port.out.model.DeviceProofBindings;
import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.DevicePlatform;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.DeviceProof;
import com.vpbank.dcp.auth.domain.model.UserName;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Base64;
import org.junit.jupiter.api.Test;

/** The proof as the apps will sign it (ML-DSA-65 with the JDK here), and everything that must not pass. */
class MlDsaDeviceProofVerifierTest {
    private static final Instant NOW = Instant.parse("2026-11-03T10:00:00Z");
    private static final String NONCE = "n0nce-n0nce-n0nce-n0nce";
    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();

    private final MlDsaDeviceProofVerifier verifier = new MlDsaDeviceProofVerifier(Clock.fixed(NOW, ZoneOffset.UTC));
    private final KeyPair deviceKeyPair = generateDeviceKey();
    private final String storedJwk = jwkOf(deviceKeyPair);
    private final String tokenKey = tokenKey();
    private final DeviceProofBindings bindings = new DeviceProofBindings(new UserName("alice"), Channel.MOBILE,
            new DeviceId("dev-1"), DevicePlatform.ANDROID, tokenKey);

    @Test
    void aProofSignedByTheStoredKeyForThisLoginIsProven() throws Exception {
        DeviceProof proof = sign(deviceKeyPair, NOW, NONCE, bindings);

        Outcome outcome = verifier.verify(storedJwk, proof, bindings);

        assertThat(outcome).isEqualTo(new Outcome.Proven(NOW.plusSeconds(120 + 5)));
        // The stored JWK may list its members in another order: same key.
        String reordered = "{\"pub\":\"" + pub(deviceKeyPair) + "\",\"kty\":\"AKP\",\"alg\":\"ML-DSA-65\"}";
        assertThat(verifier.verify(reordered, proof, bindings)).isInstanceOf(Outcome.Proven.class);
    }

    @Test
    void anotherKeyAnotherLoginOrATamperedSignatureIsRejected() throws Exception {
        DeviceProof proof = sign(deviceKeyPair, NOW, NONCE, bindings);
        KeyPair otherKeyPair = generateDeviceKey();

        assertThat(verifier.verify(jwkOf(otherKeyPair), proof, bindings)).isInstanceOf(Outcome.Rejected.class);
        assertThat(verifier.verify(storedJwk, sign(otherKeyPair, NOW, NONCE, bindings), bindings))
                .isInstanceOf(Outcome.Rejected.class);
        for (DeviceProofBindings otherLogin : new DeviceProofBindings[] {
                new DeviceProofBindings(new UserName("bob"), Channel.MOBILE, new DeviceId("dev-1"), DevicePlatform.ANDROID, tokenKey),
                new DeviceProofBindings(new UserName("alice"), Channel.MOBILE, new DeviceId("dev-2"), DevicePlatform.ANDROID, tokenKey),
                new DeviceProofBindings(new UserName("alice"), Channel.MOBILE, new DeviceId("dev-1"), DevicePlatform.IOS, tokenKey),
                new DeviceProofBindings(new UserName("alice"), Channel.MOBILE, new DeviceId("dev-1"), DevicePlatform.ANDROID, tokenKey())}) {
            assertThat(verifier.verify(storedJwk, proof, otherLogin)).as(otherLogin.toString()).isInstanceOf(Outcome.Rejected.class);
        }
        // Signed for one moment or nonce, presented with another.
        assertThat(verifier.verify(storedJwk, new DeviceProof(NOW.plusSeconds(1), NONCE, proof.signature()), bindings))
                .isInstanceOf(Outcome.Rejected.class);
        assertThat(verifier.verify(storedJwk, new DeviceProof(NOW, "other-nonce-other-nonce", proof.signature()), bindings))
                .isInstanceOf(Outcome.Rejected.class);

        byte[] flipped = proof.signature();
        flipped[flipped.length - 1] ^= 0x01;
        assertThat(verifier.verify(storedJwk, new DeviceProof(NOW, NONCE, flipped), bindings)).isInstanceOf(Outcome.Rejected.class);
        assertThat(verifier.verify(storedJwk, new DeviceProof(NOW, NONCE, Arrays.copyOf(flipped, 3308)), bindings))
                .isInstanceOf(Outcome.Rejected.class);
    }

    @Test
    void theProofIsRecentAndNotFromTheFuture() throws Exception {
        assertThat(verifier.verify(storedJwk, sign(deviceKeyPair, NOW.minusSeconds(126), NONCE, bindings), bindings))
                .as("older than two minutes").isInstanceOf(Outcome.Rejected.class);
        assertThat(verifier.verify(storedJwk, sign(deviceKeyPair, NOW.plusSeconds(6), NONCE, bindings), bindings))
                .as("signed in the future").isInstanceOf(Outcome.Rejected.class);
        assertThat(verifier.verify(storedJwk, sign(deviceKeyPair, NOW.minusSeconds(124), NONCE, bindings), bindings))
                .as("within skew").isInstanceOf(Outcome.Proven.class);
        assertThat(verifier.verify(storedJwk, sign(deviceKeyPair, NOW.plusSeconds(4), NONCE, bindings), bindings))
                .as("within skew").isInstanceOf(Outcome.Proven.class);
    }

    @Test
    void theStoredKeyMustBeAnMlDsa65PublicJwk() throws Exception {
        DeviceProof proof = sign(deviceKeyPair, NOW, NONCE, bindings);
        String pub = pub(deviceKeyPair);

        for (String badJwk : new String[] {
                "{\"alg\":\"ML-DSA-65\",\"kty\":\"AKP\"}",
                "{\"alg\":\"ML-DSA-65\",\"kty\":\"AKP\",\"pub\":\"" + pub + "\",\"priv\":\"x\"}",
                "{\"alg\":\"ML-DSA-44\",\"kty\":\"AKP\",\"pub\":\"" + pub + "\"}",
                "{\"alg\":\"ML-DSA-65\",\"kty\":\"EC\",\"pub\":\"" + pub + "\"}",
                "{\"alg\":\"ML-DSA-65\",\"kty\":\"AKP\",\"pub\":\"" + pub.substring(4) + "\"}",
                "{\"alg\":\"ML-DSA-65\",\"kty\":\"AKP\",\"pub\":\"" + pub + "==\"}",
                "{\"alg\":\"ML-DSA-65\",\"kty\":\"AKP\",\"pub\":{\"x\":\"y\"}}",
                "not json",
                tokenKey}) {
            assertThat(verifier.verify(badJwk, proof, bindings)).as(badJwk).isInstanceOf(Outcome.Rejected.class);
        }
        assertThat(verifier.verify(null, proof, bindings)).isInstanceOf(Outcome.Rejected.class);
    }

    @Test
    void theSignedBytesAreTheLengthPrefixedFieldsInContractOrder() {
        DeviceProof proof = new DeviceProof(Instant.ofEpochSecond(1762164000L), NONCE, new byte[] {1});
        byte[] signed = MlDsaDeviceProofVerifier.signedBytes(proof, bindings);

        // 4-byte big-endian length, then the UTF-8 field; the label first, the nonce last.
        assertThat(Arrays.copyOf(signed, 4 + 25)).containsExactly(concat(new byte[] {0, 0, 0, 25},
                "DCP-LOGIN-DEVICE-PROOF-V1".getBytes()));
        byte[] tail = Arrays.copyOfRange(signed, signed.length - 4 - NONCE.length(), signed.length);
        assertThat(tail).containsExactly(concat(new byte[] {0, 0, 0, (byte) NONCE.length()}, NONCE.getBytes()));
        assertThat(new String(signed, java.nio.charset.StandardCharsets.ISO_8859_1))
                .contains("alice").contains("MOBILE").contains("dev-1").contains("ANDROID").contains("1762164000");
    }

    // ---- what the app does ----

    private static KeyPair generateDeviceKey() {
        try {
            return KeyPairGenerator.getInstance("ML-DSA-65").generateKeyPair();
        } catch (Exception failure) {
            throw new IllegalStateException(failure);
        }
    }

    /** The raw 1952-byte public key is the SPKI minus its 22-byte DER prefix. */
    private static String pub(KeyPair keyPair) {
        byte[] spki = keyPair.getPublic().getEncoded();
        return B64.encodeToString(Arrays.copyOfRange(spki, spki.length - 1952, spki.length));
    }

    private static String jwkOf(KeyPair keyPair) {
        return "{\"alg\":\"ML-DSA-65\",\"kty\":\"AKP\",\"pub\":\"" + pub(keyPair) + "\"}";
    }

    private static DeviceProof sign(KeyPair keyPair, Instant issuedAt, String nonce, DeviceProofBindings bindings)
            throws Exception {
        DeviceProof unsigned = new DeviceProof(issuedAt, nonce, new byte[] {0});
        Signature signer = Signature.getInstance("ML-DSA-65");
        signer.initSign(keyPair.getPrivate());
        signer.update(MlDsaDeviceProofVerifier.signedBytes(unsigned, bindings));
        return new DeviceProof(issuedAt, nonce, signer.sign());
    }

    private static String tokenKey() {
        try {
            return new ECKeyGenerator(Curve.P_256).generate().toPublicJWK().toJSONString();
        } catch (Exception failure) {
            throw new IllegalStateException(failure);
        }
    }

    private static byte[] concat(byte[] head, byte[] tail) {
        byte[] out = Arrays.copyOf(head, head.length + tail.length);
        System.arraycopy(tail, 0, out, head.length, tail.length);
        return out;
    }
}
