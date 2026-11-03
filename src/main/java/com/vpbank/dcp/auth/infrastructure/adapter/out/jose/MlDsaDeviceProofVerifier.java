package com.vpbank.dcp.auth.infrastructure.adapter.out.jose;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.ECKey;
import com.vpbank.dcp.auth.application.port.out.gateway.DeviceProofVerifier;
import com.vpbank.dcp.auth.application.port.out.model.DeviceProofBindings;
import com.vpbank.dcp.auth.domain.model.DeviceSigningKey;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
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
 * The login device proof (slice 13) as a compact JWS signed with ML-DSA-65 (FIPS 204), verified with the
 * JDK's own {@code Signature}; Nimbus has no ML-DSA, so the JWS is parsed here, strictly.
 *
 * <p>Device key: a JWK {@code {"alg":"ML-DSA-65","kty":"AKP","pub":<1952 bytes, base64url>}} (JOSE profile of
 * draft-ietf-cose-dilithium); its canonical text has exactly those members in that order, and the thumbprint
 * is base64url(SHA-256(canonical text)). Header: exactly {@code alg=ML-DSA-65}, {@code typ=bank-login-device-proof+jwt},
 * {@code kid=<thumbprint>}. Claims: exactly {@code v=1, purpose=LOGIN_DEVICE_PROOF, userName, channel, deviceId,
 * platform, tokenKeyJkt (RFC 7638 thumbprint of the login's token key), iat, exp, jti}; {@code exp − iat ≤ 120 s},
 * 5 s of clock skew. Every mismatch is the same {@link Outcome.Rejected}.
 */
@RequiredArgsConstructor
public final class MlDsaDeviceProofVerifier implements DeviceProofVerifier {
    static final String ALGORITHM = "ML-DSA-65";
    static final String KEY_TYPE = "AKP";
    static final String PROOF_TYPE = "bank-login-device-proof+jwt";
    static final String PURPOSE = "LOGIN_DEVICE_PROOF";
    static final int VERSION = 1;
    static final Duration MAX_LIFETIME = Duration.ofSeconds(120);
    static final Duration MAX_SKEW = Duration.ofSeconds(5);
    private static final int PUBLIC_KEY_LENGTH = 1952;
    private static final int SIGNATURE_LENGTH = 3309;
    private static final int MAX_PROOF_ID_LENGTH = 128;
    /** DER SubjectPublicKeyInfo prefix the JDK reads an ML-DSA-65 public key under (OID 2.16.840.1.101.3.4.3.18). */
    private static final byte[] SPKI_PREFIX = HexFormat.of().parseHex("308207b2300b0609608648016503040312038207a100");
    private static final Set<String> JWK_MEMBERS = Set.of("alg", "kty", "pub");
    private static final Set<String> HEADER_MEMBERS = Set.of("alg", "typ", "kid");
    private static final Set<String> CLAIMS = Set.of("v", "purpose", "userName", "channel", "deviceId", "platform",
            "tokenKeyJkt", "iat", "exp", "jti");
    private static final Pattern BASE64URL = Pattern.compile("[A-Za-z0-9_-]+");
    private static final JsonMapper JSON = JsonMapper.builder().build();

    @NonNull private final Clock clock;

    @Override
    public Outcome verify(String devicePublicJwk, String compactProof, DeviceProofBindings bindings) {
        Objects.requireNonNull(bindings, "bindings");
        if (devicePublicJwk == null || compactProof == null) {
            return new Outcome.Rejected();
        }
        try {
            DeviceSigningKey deviceKey = canonicalKey(devicePublicJwk);
            if (deviceKey == null) {
                return new Outcome.Rejected();
            }

            String[] parts = compactProof.split("\\.", -1);
            if (parts.length != 3) {
                return new Outcome.Rejected();
            }
            Map<String, JsonNode> header = flatObject(decodeBase64Url(parts[0]));
            Map<String, JsonNode> claims = flatObject(decodeBase64Url(parts[1]));
            byte[] signature = decodeBase64Url(parts[2]);
            if (header == null || claims == null || signature == null) {
                return new Outcome.Rejected();
            }

            boolean expectedHeader = HEADER_MEMBERS.equals(header.keySet())
                    && ALGORITHM.equals(text(header, "alg"))
                    && PROOF_TYPE.equals(text(header, "typ"))
                    && deviceKey.thumbprint().equals(text(header, "kid"));
            if (!expectedHeader) {
                return new Outcome.Rejected();
            }

            byte[] signingInput = (parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII);
            if (signature.length != SIGNATURE_LENGTH || !signedBy(deviceKey, signingInput, signature)) {
                return new Outcome.Rejected();
            }

            boolean boundToThisLogin = CLAIMS.equals(claims.keySet())
                    && integer(claims, "v") == VERSION
                    && PURPOSE.equals(text(claims, "purpose"))
                    && bindings.userName().value().equals(text(claims, "userName"))
                    && bindings.channel().name().equals(text(claims, "channel"))
                    && bindings.deviceId().value().equals(text(claims, "deviceId"))
                    && bindings.platform().name().equals(text(claims, "platform"))
                    && tokenKeyThumbprint(bindings.tokenEncryptionKey()).equals(text(claims, "tokenKeyJkt"))
                    && hasUsableProofId(text(claims, "jti"));
            if (!boundToThisLogin) {
                return new Outcome.Rejected();
            }

            Instant issuedAt = Instant.ofEpochSecond(integer(claims, "iat"));
            Instant expiresAt = Instant.ofEpochSecond(integer(claims, "exp"));
            if (!withinLifetime(issuedAt, expiresAt)) {
                return new Outcome.Rejected();
            }

            return new Outcome.Proven(deviceKey, text(claims, "jti"), expiresAt.plus(MAX_SKEW));
        } catch (GeneralSecurityException | IllegalArgumentException | ArithmeticException | NullPointerException invalid) {
            // A member of the wrong JSON type, an unparsable number or an undecodable key lands here.
            return new Outcome.Rejected();
        }
    }

    /** The JWK as the device sent it, reduced to its canonical text; null when it is not an ML-DSA-65 public JWK. */
    static DeviceSigningKey canonicalKey(String devicePublicJwk) {
        Map<String, JsonNode> jwk = flatObject(devicePublicJwk.getBytes(StandardCharsets.UTF_8));
        if (jwk == null || !JWK_MEMBERS.equals(jwk.keySet())) {
            return null;
        }
        String publicKeyText = text(jwk, "pub");
        boolean expectedKey = ALGORITHM.equals(text(jwk, "alg"))
                && KEY_TYPE.equals(text(jwk, "kty"))
                && publicKeyText != null
                && BASE64URL.matcher(publicKeyText).matches();
        if (!expectedKey) {
            return null;
        }
        byte[] rawPublicKey = decodeBase64Url(publicKeyText);
        if (rawPublicKey == null || rawPublicKey.length != PUBLIC_KEY_LENGTH) {
            return null;
        }

        String canonicalJwk = "{\"alg\":\"" + ALGORITHM + "\",\"kty\":\"" + KEY_TYPE + "\",\"pub\":\"" + publicKeyText + "\"}";
        return new DeviceSigningKey(canonicalJwk, thumbprintOf(canonicalJwk));
    }

    private static boolean signedBy(DeviceSigningKey deviceKey, byte[] signingInput, byte[] signature)
            throws GeneralSecurityException {
        Map<String, JsonNode> jwk = flatObject(deviceKey.publicJwk().getBytes(StandardCharsets.UTF_8));
        byte[] rawPublicKey = decodeBase64Url(text(jwk, "pub"));
        byte[] encodedPublicKey = new byte[SPKI_PREFIX.length + rawPublicKey.length];
        System.arraycopy(SPKI_PREFIX, 0, encodedPublicKey, 0, SPKI_PREFIX.length);
        System.arraycopy(rawPublicKey, 0, encodedPublicKey, SPKI_PREFIX.length, rawPublicKey.length);
        PublicKey publicKey = KeyFactory.getInstance("ML-DSA").generatePublic(new X509EncodedKeySpec(encodedPublicKey));

        Signature verifier = Signature.getInstance(ALGORITHM);
        verifier.initVerify(publicKey);
        verifier.update(signingInput);
        return verifier.verify(signature);
    }

    /** Issued already, not expired, and never valid for more than two minutes. */
    private boolean withinLifetime(Instant issuedAt, Instant expiresAt) {
        Instant now = clock.instant();
        boolean lifetimeIsShort = expiresAt.isAfter(issuedAt)
                && Duration.between(issuedAt, expiresAt).compareTo(MAX_LIFETIME) <= 0;
        boolean alreadyIssued = issuedAt.minus(MAX_SKEW).isBefore(now);
        boolean notExpired = expiresAt.plus(MAX_SKEW).isAfter(now);
        return lifetimeIsShort && alreadyIssued && notExpired;
    }

    /** RFC 7638 thumbprint of the login's P-256 token key, as the app computes it. */
    private static String tokenKeyThumbprint(String tokenEncryptionKey) {
        try {
            return ECKey.parse(tokenEncryptionKey).computeThumbprint().toString();
        } catch (ParseException | JOSEException | ClassCastException invalid) {
            throw new IllegalArgumentException("The token key is not a JWK", invalid);
        }
    }

    private static boolean hasUsableProofId(String proofId) {
        return proofId != null && !proofId.isBlank() && proofId.length() <= MAX_PROOF_ID_LENGTH;
    }

    private static String thumbprintOf(String canonicalJwk) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(canonicalJwk.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (GeneralSecurityException failure) {
            throw new IllegalStateException("SHA-256 is not available", failure);
        }
    }

    /** A JSON object whose members are strings or integers; null for anything else (nested values, arrays, text). */
    private static Map<String, JsonNode> flatObject(byte[] json) {
        if (json == null) {
            return null;
        }
        JsonNode node;
        try {
            node = JSON.readTree(json);
        } catch (JacksonException malformed) {
            return null;
        }
        if (node == null || !node.isObject()) {
            return null;
        }
        Map<String, JsonNode> members = new java.util.LinkedHashMap<>();
        for (Map.Entry<String, JsonNode> member : node.properties()) {
            boolean flat = member.getValue().isString() || member.getValue().isIntegralNumber();
            if (!flat) {
                return null;
            }
            members.put(member.getKey(), member.getValue());
        }
        return members;
    }

    private static String text(Map<String, JsonNode> object, String member) {
        JsonNode value = object.get(member);
        return value != null && value.isString() ? value.stringValue() : null;
    }

    private static long integer(Map<String, JsonNode> object, String member) {
        JsonNode value = object.get(member);
        if (value == null || !value.isIntegralNumber()) {
            throw new IllegalArgumentException(member + " is not an integer");
        }
        return value.longValue();
    }

    /** Strict base64url: the URL alphabet, no padding; null otherwise. */
    private static byte[] decodeBase64Url(String text) {
        if (text == null || text.isEmpty() || !BASE64URL.matcher(text).matches()) {
            return null;
        }
        return Base64.getUrlDecoder().decode(text);
    }
}
