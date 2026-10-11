package com.vpbank.dcp.infrastructure.adapter.out.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import com.vpbank.dcp.testsupport.ContractVectors;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

class BankingTokenEnvelopeIssuerTest {

    private static final Instant NOW = Instant.parse("2026-10-11T12:00:00Z");

    @Test
    void sharedSoftwareKeyVectorDecryptsAndReceiptMatchesExactEnvelope() throws Exception {
        JsonNode vector = ContractVectors.loadSoftwareKeys();
        ECKey recipient = ECKey.parse(vector.path("recipientPrivateJwk").toString());
        ECKey receiptKey = ECKey.parse(vector.path("receiptPublicJwk").toString());
        String compact = vector.path("tokenEnvelope").asText();
        JWEObject envelope = JWEObject.parse(compact);
        envelope.decrypt(new ECDHDecrypter(recipient));
        JsonNode payload = JsonMapper.builder().build().readTree(envelope.getPayload().toString());
        SignedJWT receipt = SignedJWT.parse(vector.path("receipt").asText());
        String digest = Base64.getUrlEncoder().withoutPadding().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(compact.getBytes(StandardCharsets.US_ASCII)));

        assertEquals(vector.path("expected").path("token").asText(), payload.path("accessToken").asText());
        assertEquals(vector.path("expected").path("operationId").asText(),
                payload.path("operationId").asText());
        assertEquals(vector.path("expected").path("status").asText(), payload.path("status").asText());
        assertEquals("ECDH-ES", envelope.getHeader().getAlgorithm().getName());
        assertEquals("A256GCM", envelope.getHeader().getEncryptionMethod().getName());
        assertTrue(receipt.verify(new ECDSAVerifier(receiptKey)));
        assertEquals(digest, receipt.getJWTClaimsSet().getStringClaim("envelope_sha256"));
        assertEquals(recipient.computeThumbprint().toString(),
                receipt.getJWTClaimsSet().getStringClaim("recipient_jkt"));
        assertEquals(vector.path("expected").path("audience").asText(),
                receipt.getJWTClaimsSet().getAudience().getFirst());
        assertEquals(vector.path("expected").path("requestKeyThumbprint").asText(),
                receipt.getJWTClaimsSet().getStringClaim("request_key_jkt"));
        assertEquals(vector.path("expected").path("deviceKeyThumbprint").asText(),
                receipt.getJWTClaimsSet().getStringClaim("device_key_jkt"));
        assertFalse(digest.equals(Base64.getUrlEncoder().withoutPadding().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(
                        (compact + "tampered").getBytes(StandardCharsets.US_ASCII)))));
    }

    @Test
    void appCanDecryptItsOwnEnvelopeAndVerifyReceiptBinding() throws Exception {
        var recipient = new ECKeyGenerator(Curve.P_256).keyID("app-kenc").generate();
        var receiptKey = new ECKeyGenerator(Curve.P_256).keyID("receipt-v1").generate();
        var issuer = new BankingTokenEnvelopeIssuer("https://auth.bank.test", receiptKey,
                JsonMapper.builder().build(), Clock.fixed(NOW, ZoneOffset.UTC));
        var context = new TokenDeliveryContext(
                UUID.fromString("44444444-4444-4444-8444-444444444444"),
                "neo-mobile", BankingTokenStatus.ACTIVE, "request-jkt", "device-jkt",
                NOW.plusSeconds(900));

        EncryptedBankingToken delivered = issuer.issue(new OpaqueBankingToken("k1.private-token"),
                recipient.toPublicJWK(), context);
        JWEObject envelope = JWEObject.parse(delivered.tokenEnvelope());
        envelope.decrypt(new ECDHDecrypter(recipient));
        JsonNode payload = JsonMapper.builder().build().readTree(envelope.getPayload().toString());
        SignedJWT receipt = SignedJWT.parse(delivered.receipt());
        String digest = Base64.getUrlEncoder().withoutPadding().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(
                        delivered.tokenEnvelope().getBytes(StandardCharsets.US_ASCII)));

        assertEquals("k1.private-token", payload.path("accessToken").asText());
        assertEquals("ACTIVE", payload.path("status").asText());
        assertEquals("DPoP", payload.path("tokenType").asText());
        assertEquals("ECDH-ES", envelope.getHeader().getAlgorithm().getName());
        assertEquals("A256GCM", envelope.getHeader().getEncryptionMethod().getName());
        assertTrue(receipt.verify(new ECDSAVerifier(receiptKey.toPublicJWK())));
        assertEquals(digest, receipt.getJWTClaimsSet().getStringClaim("envelope_sha256"));
        assertEquals(recipient.computeThumbprint().toString(),
                receipt.getJWTClaimsSet().getStringClaim("recipient_jkt"));
        assertFalse(delivered.toString().contains("private-token"));
    }

    @Test
    void differentAppKeyCannotDecryptAndPrivateRecipientIsRejected() throws Exception {
        var recipient = new ECKeyGenerator(Curve.P_256).keyID("app-kenc").generate();
        var other = new ECKeyGenerator(Curve.P_256).keyID("other-kenc").generate();
        var receiptKey = new ECKeyGenerator(Curve.P_256).keyID("receipt-v1").generate();
        var issuer = new BankingTokenEnvelopeIssuer("https://auth.bank.test", receiptKey,
                JsonMapper.builder().build(), Clock.fixed(NOW, ZoneOffset.UTC));
        var context = new TokenDeliveryContext(UUID.randomUUID(), "neo-mobile",
                BankingTokenStatus.PENDING_MFA, "request-jkt", null, NOW.plusSeconds(120));

        assertThrows(InvalidCryptographicInputException.class,
                () -> issuer.issue(new OpaqueBankingToken("k1.private-token"), recipient, context));
        EncryptedBankingToken delivered = issuer.issue(new OpaqueBankingToken("k1.private-token"),
                recipient.toPublicJWK(), context);
        JWEObject envelope = JWEObject.parse(delivered.tokenEnvelope());
        assertThrows(Exception.class, () -> envelope.decrypt(new ECDHDecrypter(other)));
    }
}
