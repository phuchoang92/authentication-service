package com.vpbank.dcp.auth.infrastructure.adapter.out.jose;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.ECKey;
import com.vpbank.dcp.auth.application.port.out.gateway.DeviceProofVerifier;
import com.vpbank.dcp.auth.application.port.out.model.DeviceProofBindings;
import com.vpbank.dcp.auth.domain.model.DeviceProof;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * The login device proof (slice 13) as a raw ML-DSA-65 signature (FIPS 204, empty context), verified with
 * the JDK's own {@code Signature}. No JOSE: the algorithm is the stored key's, nothing on the wire names it.
 *
 * <p>Stored device key: a JWK {@code {"alg":"ML-DSA-65","kty":"AKP","pub":<1952 bytes, base64url>}} (JOSE
 * profile of draft-ietf-cose-dilithium), exactly those members in any order. Signed bytes: every field
 * length-prefixed (4-byte big-endian length, then UTF-8), in this order — {@value #LABEL}, user name, channel,
 * device ID, platform, RFC 7638 thumbprint of the login's token key, {@code issuedAt} as decimal epoch seconds,
 * nonce. {@code issuedAt} may be up to {@value #MAX_AGE_SECONDS} s old, with 5 s of clock skew either way.
 */
@RequiredArgsConstructor
public final class MlDsaDeviceProofVerifier implements DeviceProofVerifier {
    static final String LABEL = "DCP-LOGIN-DEVICE-PROOF-V1";
    static final String ALGORITHM = "ML-DSA-65";
    static final String KEY_TYPE = "AKP";
    static final int MAX_AGE_SECONDS = 120;
    static final Duration MAX_SKEW = Duration.ofSeconds(5);
    private static final Duration MAX_AGE = Duration.ofSeconds(MAX_AGE_SECONDS);
    private static final int PUBLIC_KEY_LENGTH = 1952;
    private static final int SIGNATURE_LENGTH = 3309;
    /** DER SubjectPublicKeyInfo prefix the JDK reads an ML-DSA-65 public key under (OID 2.16.840.1.101.3.4.3.18). */
    private static final byte[] SPKI_PREFIX = HexFormat.of().parseHex("308207b2300b0609608648016503040312038207a100");
    private static final Set<String> JWK_MEMBERS = Set.of("alg", "kty", "pub");
    private static final Pattern BASE64URL = Pattern.compile("[A-Za-z0-9_-]+");
    private static final JsonMapper JSON = JsonMapper.builder().build();

    @NonNull private final Clock clock;

    @Override
    public Outcome verify(String devicePublicJwk, DeviceProof proof, DeviceProofBindings bindings) {
        Objects.requireNonNull(proof, "proof");
        Objects.requireNonNull(bindings, "bindings");
        if (devicePublicJwk == null) {
            return new Outcome.Rejected();
        }
        try {
            PublicKey deviceKey = storedKey(devicePublicJwk);
            if (deviceKey == null) {
                return new Outcome.Rejected();
            }
            if (!withinWindow(proof.issuedAt())) {
                return new Outcome.Rejected();
            }

            byte[] signedBytes = signedBytes(proof, bindings);
            byte[] signature = proof.signature();
            if (signature.length != SIGNATURE_LENGTH) {
                return new Outcome.Rejected();
            }
            Signature verifier = Signature.getInstance(ALGORITHM);
            verifier.initVerify(deviceKey);
            verifier.update(signedBytes);
            if (!verifier.verify(signature)) {
                return new Outcome.Rejected();
            }

            return new Outcome.Proven(proof.issuedAt().plus(MAX_AGE).plus(MAX_SKEW));
        } catch (GeneralSecurityException | IllegalArgumentException invalid) {
            // A stored key the JDK cannot read, or a token key that is not a JWK.
            return new Outcome.Rejected();
        }
    }

    /** The stored JWK as a JDK public key; null when it is not an ML-DSA-65 public JWK. */
    private static PublicKey storedKey(String devicePublicJwk) throws GeneralSecurityException {
        Map<String, String> jwk = flatObject(devicePublicJwk);
        boolean expectedKey = jwk != null
                && JWK_MEMBERS.equals(jwk.keySet())
                && ALGORITHM.equals(jwk.get("alg"))
                && KEY_TYPE.equals(jwk.get("kty"))
                && BASE64URL.matcher(jwk.get("pub")).matches();
        if (!expectedKey) {
            return null;
        }
        byte[] rawPublicKey = Base64.getUrlDecoder().decode(jwk.get("pub"));
        if (rawPublicKey.length != PUBLIC_KEY_LENGTH) {
            return null;
        }
        byte[] encodedPublicKey = new byte[SPKI_PREFIX.length + rawPublicKey.length];
        System.arraycopy(SPKI_PREFIX, 0, encodedPublicKey, 0, SPKI_PREFIX.length);
        System.arraycopy(rawPublicKey, 0, encodedPublicKey, SPKI_PREFIX.length, rawPublicKey.length);
        return KeyFactory.getInstance("ML-DSA").generatePublic(new X509EncodedKeySpec(encodedPublicKey));
    }

    /** Signed already (not in the future beyond the skew) and not older than the maximum age. */
    private boolean withinWindow(Instant issuedAt) {
        Instant now = clock.instant();
        boolean alreadySigned = issuedAt.minus(MAX_SKEW).isBefore(now);
        boolean stillFresh = issuedAt.plus(MAX_AGE).plus(MAX_SKEW).isAfter(now);
        return alreadySigned && stillFresh;
    }

    /** The bytes both sides sign: the fields of this login, each length-prefixed, in the contract's order. */
    static byte[] signedBytes(DeviceProof proof, DeviceProofBindings bindings) {
        List<String> fields = List.of(
                LABEL,
                bindings.userName().value(),
                bindings.channel().name(),
                bindings.deviceId().value(),
                bindings.platform().name(),
                tokenKeyThumbprint(bindings.tokenEncryptionKey()),
                Long.toString(proof.issuedAt().getEpochSecond()),
                proof.nonce());
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (String field : fields) {
            byte[] bytes = field.getBytes(StandardCharsets.UTF_8);
            out.write(bytes.length >>> 24);
            out.write(bytes.length >>> 16);
            out.write(bytes.length >>> 8);
            out.write(bytes.length);
            out.writeBytes(bytes);
        }
        return out.toByteArray();
    }

    /** RFC 7638 thumbprint of the login's P-256 token key, as the app computes it. */
    private static String tokenKeyThumbprint(String tokenEncryptionKey) {
        try {
            return ECKey.parse(tokenEncryptionKey).computeThumbprint().toString();
        } catch (ParseException | JOSEException | ClassCastException invalid) {
            throw new IllegalArgumentException("The token key is not a JWK", invalid);
        }
    }

    /** A JSON object whose members are all strings; null for anything else. */
    private static Map<String, String> flatObject(String json) {
        JsonNode node;
        try {
            node = JSON.readTree(json);
        } catch (JacksonException malformed) {
            return null;
        }
        if (node == null || !node.isObject()) {
            return null;
        }
        Map<String, String> members = new java.util.LinkedHashMap<>();
        for (Map.Entry<String, JsonNode> member : node.properties()) {
            if (!member.getValue().isString()) {
                return null;
            }
            members.put(member.getKey(), member.getValue().stringValue());
        }
        return members;
    }
}
