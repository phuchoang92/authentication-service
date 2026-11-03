package com.vpbank.dcp.auth.infrastructure.adapter.out.jose;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.vpbank.dcp.auth.application.port.out.gateway.DeviceProofVerifier.Outcome;
import com.vpbank.dcp.auth.application.port.out.model.DeviceProofBindings;
import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.DevicePlatform;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.UserName;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

/** The proof as the apps will sign it (ML-DSA-65 with the JDK here), and everything that must not pass. */
class MlDsaDeviceProofVerifierTest {
    private static final Instant NOW = Instant.parse("2026-11-03T10:00:00Z");
    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();

    private final MlDsaDeviceProofVerifier verifier = new MlDsaDeviceProofVerifier(Clock.fixed(NOW, ZoneOffset.UTC));
    private final KeyPair deviceKeyPair = generateDeviceKey();
    private final String deviceJwk = jwkOf(deviceKeyPair);
    private final String tokenKey = tokenKey();
    private final DeviceProofBindings bindings = new DeviceProofBindings(new UserName("alice"), Channel.MOBILE,
            new DeviceId("dev-1"), DevicePlatform.ANDROID, tokenKey);

    @Test
    void aProofSignedByTheDeviceKeyForThisLoginIsProvenAndTheKeyIsCanonical() throws Exception {
        String proof = sign(deviceKeyPair, header(deviceJwk), claims());

        Outcome outcome = verifier.verify(deviceJwk, proof, bindings);

        assertThat(outcome).isInstanceOf(Outcome.Proven.class);
        Outcome.Proven proven = (Outcome.Proven) outcome;
        assertThat(proven.proofId()).isEqualTo("jti-1");
        assertThat(proven.rememberUntil()).isEqualTo(NOW.plusSeconds(60 + 5));
        assertThat(proven.key().publicJwk()).startsWith("{\"alg\":\"ML-DSA-65\",\"kty\":\"AKP\",\"pub\":\"");
        assertThat(proven.key().thumbprint()).isEqualTo(thumbprint(proven.key().publicJwk()));

        // The same key sent with its members in another order is the same canonical key.
        String reordered = "{\"pub\":\"" + pub(deviceKeyPair) + "\",\"kty\":\"AKP\",\"alg\":\"ML-DSA-65\"}";
        Outcome same = verifier.verify(reordered, proof, bindings);
        assertThat(((Outcome.Proven) same).key()).isEqualTo(proven.key());
    }

    @Test
    void anotherKeyAnotherLoginOrATamperedProofIsRejected() throws Exception {
        String proof = sign(deviceKeyPair, header(deviceJwk), claims());
        KeyPair otherKeyPair = generateDeviceKey();

        assertThat(verifier.verify(jwkOf(otherKeyPair), proof, bindings)).isInstanceOf(Outcome.Rejected.class);
        assertThat(verifier.verify(deviceJwk, sign(otherKeyPair, header(deviceJwk), claims()), bindings))
                .isInstanceOf(Outcome.Rejected.class);
        assertThat(verifier.verify(deviceJwk, proof, new DeviceProofBindings(new UserName("bob"), Channel.MOBILE,
                new DeviceId("dev-1"), DevicePlatform.ANDROID, tokenKey))).isInstanceOf(Outcome.Rejected.class);
        assertThat(verifier.verify(deviceJwk, proof, new DeviceProofBindings(new UserName("alice"), Channel.MOBILE,
                new DeviceId("dev-2"), DevicePlatform.ANDROID, tokenKey))).isInstanceOf(Outcome.Rejected.class);
        assertThat(verifier.verify(deviceJwk, proof, new DeviceProofBindings(new UserName("alice"), Channel.MOBILE,
                new DeviceId("dev-1"), DevicePlatform.IOS, tokenKey))).isInstanceOf(Outcome.Rejected.class);
        assertThat(verifier.verify(deviceJwk, proof, new DeviceProofBindings(new UserName("alice"), Channel.MOBILE,
                new DeviceId("dev-1"), DevicePlatform.ANDROID, tokenKey()))).isInstanceOf(Outcome.Rejected.class);

        String[] parts = proof.split("\\.");
        String flippedSignature = parts[0] + "." + parts[1] + "." + flipLast(parts[2]);
        assertThat(verifier.verify(deviceJwk, flippedSignature, bindings)).isInstanceOf(Outcome.Rejected.class);
        assertThat(verifier.verify(deviceJwk, parts[0] + "." + parts[1], bindings)).isInstanceOf(Outcome.Rejected.class);
        assertThat(verifier.verify(deviceJwk, proof + "=", bindings)).isInstanceOf(Outcome.Rejected.class);
        assertThat(verifier.verify(deviceJwk, "", bindings)).isInstanceOf(Outcome.Rejected.class);
        assertThat(verifier.verify(deviceJwk, null, bindings)).isInstanceOf(Outcome.Rejected.class);
    }

    @Test
    void theHeaderAndTheClaimSetMustBeExactlyTheProfile() throws Exception {
        Map<String, Object> header = header(deviceJwk);
        Map<String, Object> claims = claims();

        assertThat(verifier.verify(deviceJwk, sign(deviceKeyPair, with(header, "alg", "ES256"), claims), bindings))
                .isInstanceOf(Outcome.Rejected.class);
        assertThat(verifier.verify(deviceJwk, sign(deviceKeyPair, with(header, "typ", "JWT"), claims), bindings))
                .isInstanceOf(Outcome.Rejected.class);
        assertThat(verifier.verify(deviceJwk, sign(deviceKeyPair, with(header, "kid", "other"), claims), bindings))
                .isInstanceOf(Outcome.Rejected.class);
        assertThat(verifier.verify(deviceJwk, sign(deviceKeyPair, with(header, "jwk", "{}"), claims), bindings))
                .isInstanceOf(Outcome.Rejected.class);
        assertThat(verifier.verify(deviceJwk, sign(deviceKeyPair, without(header, "kid"), claims), bindings))
                .isInstanceOf(Outcome.Rejected.class);

        assertThat(verifier.verify(deviceJwk, sign(deviceKeyPair, header, with(claims, "v", 2)), bindings))
                .isInstanceOf(Outcome.Rejected.class);
        assertThat(verifier.verify(deviceJwk, sign(deviceKeyPair, header, with(claims, "purpose", "OTHER")), bindings))
                .isInstanceOf(Outcome.Rejected.class);
        assertThat(verifier.verify(deviceJwk, sign(deviceKeyPair, header, with(claims, "extra", "x")), bindings))
                .isInstanceOf(Outcome.Rejected.class);
        assertThat(verifier.verify(deviceJwk, sign(deviceKeyPair, header, without(claims, "jti")), bindings))
                .isInstanceOf(Outcome.Rejected.class);
        assertThat(verifier.verify(deviceJwk, sign(deviceKeyPair, header, with(claims, "jti", " ")), bindings))
                .isInstanceOf(Outcome.Rejected.class);
        assertThat(verifier.verify(deviceJwk, sign(deviceKeyPair, header, with(claims, "iat", "soon")), bindings))
                .isInstanceOf(Outcome.Rejected.class);
    }

    @Test
    void theProofIsShortLivedAndCurrent() throws Exception {
        Map<String, Object> header = header(deviceJwk);
        long now = NOW.getEpochSecond();

        assertThat(verifier.verify(deviceJwk, sign(deviceKeyPair, header, claims(now - 130, now - 10)), bindings))
                .as("expired").isInstanceOf(Outcome.Rejected.class);
        assertThat(verifier.verify(deviceJwk, sign(deviceKeyPair, header, claims(now + 10, now + 70)), bindings))
                .as("issued in the future").isInstanceOf(Outcome.Rejected.class);
        assertThat(verifier.verify(deviceJwk, sign(deviceKeyPair, header, claims(now, now + 121)), bindings))
                .as("longer than two minutes").isInstanceOf(Outcome.Rejected.class);
        assertThat(verifier.verify(deviceJwk, sign(deviceKeyPair, header, claims(now + 60, now)), bindings))
                .as("expires before issue").isInstanceOf(Outcome.Rejected.class);
        assertThat(verifier.verify(deviceJwk, sign(deviceKeyPair, header, claims(now - 4, now + 120 - 4)), bindings))
                .as("within skew").isInstanceOf(Outcome.Proven.class);
    }

    @Test
    void theDeviceKeyMustBeAnMlDsa65PublicJwk() throws Exception {
        String proof = sign(deviceKeyPair, header(deviceJwk), claims());
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

    private static String thumbprint(String canonicalJwk) throws Exception {
        return B64.encodeToString(MessageDigest.getInstance("SHA-256").digest(canonicalJwk.getBytes(StandardCharsets.UTF_8)));
    }

    private static Map<String, Object> header(String canonicalJwk) throws Exception {
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", "ML-DSA-65");
        header.put("typ", "bank-login-device-proof+jwt");
        header.put("kid", thumbprint(canonicalJwk));
        return header;
    }

    private Map<String, Object> claims() throws Exception {
        return claims(NOW.getEpochSecond(), NOW.getEpochSecond() + 60);
    }

    private Map<String, Object> claims(long issuedAt, long expiresAt) throws Exception {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("v", 1);
        claims.put("purpose", "LOGIN_DEVICE_PROOF");
        claims.put("userName", "alice");
        claims.put("channel", "MOBILE");
        claims.put("deviceId", "dev-1");
        claims.put("platform", "ANDROID");
        claims.put("tokenKeyJkt", ECKey.parse(tokenKey).computeThumbprint().toString());
        claims.put("iat", issuedAt);
        claims.put("exp", expiresAt);
        claims.put("jti", "jti-1");
        return claims;
    }

    private static String sign(KeyPair keyPair, Map<String, Object> header, Map<String, Object> claims) throws Exception {
        String signingInput = B64.encodeToString(JSON.writeValueAsBytes(header)) + "."
                + B64.encodeToString(JSON.writeValueAsBytes(claims));
        Signature signer = Signature.getInstance("ML-DSA-65");
        signer.initSign(keyPair.getPrivate());
        signer.update(signingInput.getBytes(StandardCharsets.US_ASCII));
        return signingInput + "." + B64.encodeToString(signer.sign());
    }

    private static String tokenKey() {
        try {
            return new ECKeyGenerator(Curve.P_256).generate().toPublicJWK().toJSONString();
        } catch (Exception failure) {
            throw new IllegalStateException(failure);
        }
    }

    private static Map<String, Object> with(Map<String, Object> object, String member, Object value) {
        Map<String, Object> copy = new LinkedHashMap<>(object);
        copy.put(member, value);
        return copy;
    }

    private static Map<String, Object> without(Map<String, Object> object, String member) {
        Map<String, Object> copy = new LinkedHashMap<>(object);
        copy.remove(member);
        return copy;
    }

    private static String flipLast(String base64url) {
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        char last = base64url.charAt(base64url.length() - 1);
        char changed = alphabet.charAt((alphabet.indexOf(last) + 4) % 64);
        return base64url.substring(0, base64url.length() - 1) + changed;
    }
}
