package com.vpbank.dcp.infrastructure.adapter.out.crypto;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Objects;

/**
 * Checks the ciphertext envelope before forwarding it unchanged to its verifier.
 */
public final class JweEnvelopeInspector {

    private final Sha256Digests digests;
    private final StrictJoseJson strictJson;

    public JweEnvelopeInspector(Sha256Digests digests, StrictJoseJson strictJson) {
        this.digests = Objects.requireNonNull(digests, "digests");
        this.strictJson = Objects.requireNonNull(strictJson, "strictJson");
    }

    public InspectedEnvelope inspect(String compact, String expectedRecipientKid) {
        Objects.requireNonNull(compact, "compact");
        Objects.requireNonNull(expectedRecipientKid, "expectedRecipientKid");
        if (compact.length() > 16384 || compact.split("\\.", -1).length != 5) {
            throw new InvalidCryptographicInputException();
        }
        strictJson.checkCompactJweHeader(compact);
        try {
            JWEObject object = JWEObject.parse(compact);
            JWEHeader header = object.getHeader();
            if (!JWEAlgorithm.RSA_OAEP_256.equals(header.getAlgorithm())
                    || !EncryptionMethod.A256GCM.equals(header.getEncryptionMethod())
                    || header.getType() == null
                    || !"bank-credential+jwe".equals(header.getType().toString())
                    || !expectedRecipientKid.equals(header.getKeyID())
                    || header.getCompressionAlgorithm() != null
                    || header.getJWK() != null
                    || header.getJWKURL() != null
                    || header.getX509CertURL() != null
                    || (header.getCriticalParams() != null && !header.getCriticalParams().isEmpty())) {
                throw new InvalidCryptographicInputException();
            }
            return new InspectedEnvelope(
                    expectedRecipientKid,
                    digests.sha256(compact.getBytes(StandardCharsets.US_ASCII)));
        } catch (ParseException failure) {
            throw new InvalidCryptographicInputException(failure);
        }
    }
}
