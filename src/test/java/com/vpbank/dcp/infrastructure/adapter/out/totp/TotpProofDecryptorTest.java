package com.vpbank.dcp.infrastructure.adapter.out.totp;

import com.vpbank.dcp.core.port.out.totp.InvalidTotpProofException;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.vpbank.dcp.core.domain.totp.TotpCode;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.StrictJoseJson;
import java.time.Instant;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

class TotpProofDecryptorTest {
    private static final Instant NOW = Instant.parse("2026-10-13T06:30:00Z");
    private static final String CHALLENGE = "challenge-7enNQ8sqeKoX4Ecy";
    private static final String REQUEST_KEY = "pqqp6SVniNi1aLttWDSwcbOKxjhKl7lBB0SMIAZF_eY";

    private ECKey recipient;
    private TotpProofDecryptor decryptor;

    @BeforeEach
    void setUp() throws Exception {
        recipient = new ECKeyGenerator(Curve.P_256).keyID("totp-v1").generate();
        decryptor = new TotpProofDecryptor(recipient, new StrictJoseJson(),
                JsonMapper.builder().build());
    }

    @Test
    void acceptsOnlyTheCurrentChallengeAndRequestKey() throws Exception {
        String proof = encryptedProof(CHALLENGE, REQUEST_KEY, NOW.minusSeconds(2),
                NOW.plusSeconds(60), "123456");

        try (TotpCode code = decryptor.decrypt(proof, CHALLENGE, REQUEST_KEY, NOW)) {
            assertArrayEquals("123456".toCharArray(), code.copyDigits());
        }
        assertThrows(InvalidTotpProofException.class,
                () -> decryptor.decrypt(proof, "another-challenge", REQUEST_KEY, NOW));
        assertThrows(InvalidTotpProofException.class,
                () -> decryptor.decrypt(proof, CHALLENGE, "another-request-key", NOW));
    }

    @Test
    void rejectsExpiredAndOverlongProofs() throws Exception {
        String expired = encryptedProof(CHALLENGE, REQUEST_KEY, NOW.minusSeconds(60),
                NOW.minusSeconds(1), "123456");
        String overlong = encryptedProof(CHALLENGE, REQUEST_KEY, NOW.minusSeconds(1),
                NOW.plusSeconds(121), "123456");

        assertThrows(InvalidTotpProofException.class,
                () -> decryptor.decrypt(expired, CHALLENGE, REQUEST_KEY, NOW));
        assertThrows(InvalidTotpProofException.class,
                () -> decryptor.decrypt(overlong, CHALLENGE, REQUEST_KEY, NOW));
    }

    @Test
    void rejectsWrongRecipientOrMalformedCode() throws Exception {
        ECKey other = new ECKeyGenerator(Curve.P_256).keyID("totp-v1").generate();
        TotpProofDecryptor otherDecryptor = new TotpProofDecryptor(other,
                new StrictJoseJson(), JsonMapper.builder().build());
        String proof = encryptedProof(CHALLENGE, REQUEST_KEY, NOW, NOW.plusSeconds(30), "123456");
        String malformed = encryptedProof(CHALLENGE, REQUEST_KEY, NOW, NOW.plusSeconds(30), "12345X");

        assertThrows(InvalidTotpProofException.class,
                () -> otherDecryptor.decrypt(proof, CHALLENGE, REQUEST_KEY, NOW));
        InvalidTotpProofException rejected = assertThrows(InvalidTotpProofException.class,
                () -> decryptor.decrypt(malformed, CHALLENGE, REQUEST_KEY, NOW));
        assertNull(rejected.getCause());
    }

    private String encryptedProof(String challengeId, String requestKey, Instant issuedAt,
                                  Instant expiresAt, String code) throws Exception {
        String json = JsonMapper.builder().build().writeValueAsString(new ProofPayload(
                1, "LOGIN_TOTP", challengeId, requestKey, code,
                issuedAt.toString(), expiresAt.toString()));
        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM)
                .type(new JOSEObjectType("bank-totp-proof+jwe"))
                .keyID("totp-v1").customParam("version", 1).build();
        JWEObject jwe = new JWEObject(header, new Payload(json));
        jwe.encrypt(new ECDHEncrypter(recipient.toPublicJWK()));
        return jwe.serialize();
    }

    private record ProofPayload(int version, String purpose, String challengeId,
                                String requestKeyJkt, String code, String issuedAt,
                                String expiresAt) {
    }
}
