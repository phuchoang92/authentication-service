package com.vpbank.dcp.infrastructure.adapter.out.totp;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.vpbank.dcp.core.domain.totp.TotpCode;
import com.vpbank.dcp.core.port.out.totp.TotpProofReader;
import com.vpbank.dcp.core.port.out.totp.InvalidTotpProofException;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.StrictJoseJson;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Set;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/** Decrypts a short-lived App proof for an Auth-owned login TOTP challenge. */
public final class TotpProofDecryptor implements TotpProofReader {
    private static final String TYPE = "bank-totp-proof+jwe";
    private static final String PURPOSE = "LOGIN_TOTP";
    private static final Duration MAX_LIFETIME = Duration.ofSeconds(120);
    private static final Duration CLOCK_SKEW = Duration.ofSeconds(5);

    private final ECKey recipient;
    private final StrictJoseJson strictJson;
    private final JsonMapper json;

    public TotpProofDecryptor(ECKey recipient, StrictJoseJson strictJson, JsonMapper json) {
        this.recipient = Objects.requireNonNull(recipient, "recipient");
        this.strictJson = Objects.requireNonNull(strictJson, "strictJson");
        this.json = Objects.requireNonNull(json, "json");
        if (!recipient.isPrivate() || !Curve.P_256.equals(recipient.getCurve())
                || recipient.getKeyID() == null || recipient.getKeyID().isBlank()) {
            throw new InvalidTotpProofException();
        }
    }

    public TotpCode decrypt(String compact, String challengeId, String requestKeyThumbprint,
                            Instant now) {
        Objects.requireNonNull(challengeId, "challengeId");
        Objects.requireNonNull(requestKeyThumbprint, "requestKeyThumbprint");
        Objects.requireNonNull(now, "now");
        if (compact == null || compact.length() > 8192 || compact.length() < 100
                || challengeId.isBlank() || requestKeyThumbprint.isBlank()) {
            throw new InvalidTotpProofException();
        }
        try {
            strictJson.checkCompactJweHeader(compact);
            JWEObject jwe = JWEObject.parse(compact);
            verifyHeader(jwe.getHeader());
            jwe.decrypt(new ECDHDecrypter(recipient));
            String plaintext = jwe.getPayload().toString();
            strictJson.checkJson(plaintext);
            JsonNode proof = json.readTree(plaintext);
            verifyClaims(proof, challengeId, requestKeyThumbprint, now);
            return new TotpCode(proof.path("code").asText().toCharArray());
        } catch (ParseException | JOSEException | RuntimeException failure) {
            // Parser/crypto exceptions can contain plaintext or compact proof fragments.
            throw new InvalidTotpProofException();
        }
    }

    @Override
    public TotpCode read(String compactJwe, String challengeId, String requestKeyThumbprint,
                         Instant now) {
        return decrypt(compactJwe, challengeId, requestKeyThumbprint, now);
    }

    private void verifyHeader(JWEHeader header) {
        if (!JWEAlgorithm.ECDH_ES.equals(header.getAlgorithm())
                || !EncryptionMethod.A256GCM.equals(header.getEncryptionMethod())
                || header.getType() == null || !TYPE.equals(header.getType().toString())
                || !recipient.getKeyID().equals(header.getKeyID())
                || header.getCompressionAlgorithm() != null || header.getJWK() != null
                || header.getJWKURL() != null || header.getX509CertURL() != null
                || (header.getCriticalParams() != null && !header.getCriticalParams().isEmpty())
                || !Set.of("version").equals(header.getCustomParams().keySet())
                || !(header.getCustomParam("version") instanceof Number version)
                || !"1".equals(version.toString())) {
            throw new InvalidTotpProofException();
        }
    }

    private void verifyClaims(JsonNode proof, String challengeId, String requestKeyThumbprint,
                              Instant now) {
        if (proof.size() != 7 || !proof.path("version").isIntegralNumber()
                || proof.path("version").asInt(-1) != 1
                || !proof.path("code").isTextual()
                || !PURPOSE.equals(proof.path("purpose").asText())
                || !challengeId.equals(proof.path("challengeId").asText())
                || !requestKeyThumbprint.equals(proof.path("requestKeyJkt").asText())) {
            throw new InvalidTotpProofException();
        }
        Instant issuedAt = Instant.parse(proof.path("issuedAt").asText());
        Instant expiresAt = Instant.parse(proof.path("expiresAt").asText());
        if (issuedAt.isAfter(now.plus(CLOCK_SKEW)) || !expiresAt.isAfter(now)
                || !expiresAt.isAfter(issuedAt)
                || expiresAt.isAfter(issuedAt.plus(MAX_LIFETIME))) {
            throw new InvalidTotpProofException();
        }
    }
}
