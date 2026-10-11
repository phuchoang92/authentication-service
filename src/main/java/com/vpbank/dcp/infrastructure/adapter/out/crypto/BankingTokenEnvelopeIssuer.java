package com.vpbank.dcp.infrastructure.adapter.out.crypto;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import tools.jackson.databind.json.JsonMapper;

/** Encrypts the opaque banking token to software Kenc and signs exact-envelope delivery metadata. */
public final class BankingTokenEnvelopeIssuer {

    private static final String PURPOSE = "BANKING_TOKEN";
    private static final int VERSION = 1;

    private final String issuer;
    private final ECKey receiptKey;
    private final JsonMapper json;
    private final Clock clock;

    public BankingTokenEnvelopeIssuer(String issuer, ECKey receiptKey,
                                      JsonMapper json, Clock clock) {
        this.issuer = Objects.requireNonNull(issuer, "issuer");
        this.receiptKey = Objects.requireNonNull(receiptKey, "receiptKey");
        this.json = Objects.requireNonNull(json, "json");
        this.clock = Objects.requireNonNull(clock, "clock");
        if (!issuer.startsWith("https://") || !receiptKey.isPrivate()
                || !Curve.P_256.equals(receiptKey.getCurve())
                || receiptKey.getKeyID() == null || receiptKey.getKeyID().isBlank()) {
            throw new InvalidCryptographicInputException();
        }
    }

    public EncryptedBankingToken issue(OpaqueBankingToken token, ECKey recipient,
                                       TokenDeliveryContext context) {
        Objects.requireNonNull(token, "token");
        Objects.requireNonNull(recipient, "recipient");
        Objects.requireNonNull(context, "context");
        if (recipient.isPrivate() || !Curve.P_256.equals(recipient.getCurve())) {
            throw new InvalidCryptographicInputException();
        }
        Instant now = clock.instant();
        if (!context.tokenExpiresAt().isAfter(now)) {
            throw new InvalidCryptographicInputException();
        }
        try {
            String recipientThumbprint = recipient.computeThumbprint().toString();
            String payload = json.writeValueAsString(Map.of(
                    "version", VERSION,
                    "purpose", PURPOSE,
                    "operationId", context.operationId().toString(),
                    "status", context.status().name(),
                    "accessToken", token.exactValue(),
                    "tokenType", "DPoP",
                    "requestKeyThumbprint", context.requestKeyThumbprint(),
                    "expiresAt", context.tokenExpiresAt().toString()));
            JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES,
                    EncryptionMethod.A256GCM)
                    .type(new JOSEObjectType("banking-token+jwe"))
                    .keyID(recipientThumbprint)
                    .customParam("version", VERSION)
                    .customParam("purpose", PURPOSE)
                    .build();
            JWEObject envelope = new JWEObject(header, new Payload(payload));
            envelope.encrypt(new ECDHEncrypter(recipient));
            String compact = envelope.serialize();
            String receipt = signReceipt(compact, recipientThumbprint, context, now);
            return new EncryptedBankingToken(compact, receipt);
        } catch (JOSEException | NoSuchAlgorithmException failure) {
            throw new CryptographicProviderUnavailableException(failure);
        }
    }

    private String signReceipt(String envelope, String recipientThumbprint,
                               TokenDeliveryContext context, Instant now)
            throws JOSEException, NoSuchAlgorithmException {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(
                envelope.getBytes(StandardCharsets.US_ASCII));
        String envelopeDigest = Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        Instant receiptExpiry = now.plusSeconds(120).isBefore(context.tokenExpiresAt())
                ? now.plusSeconds(120) : context.tokenExpiresAt();
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .audience(context.appId())
                .jwtID(UUID.randomUUID().toString())
                .issueTime(Date.from(now))
                .notBeforeTime(Date.from(now))
                .expirationTime(Date.from(receiptExpiry))
                .claim("version", VERSION)
                .claim("purpose", "BANKING_TOKEN_DELIVERY")
                .claim("operation_id", context.operationId().toString())
                .claim("status", context.status().name())
                .claim("envelope_sha256", envelopeDigest)
                .claim("recipient_jkt", recipientThumbprint)
                .claim("request_key_jkt", context.requestKeyThumbprint());
        if (context.deviceKeyThumbprint() != null) {
            claims.claim("device_key_jkt", context.deviceKeyThumbprint());
        }
        SignedJWT receipt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("banking-token-receipt+jwt"))
                .keyID(receiptKey.getKeyID())
                .build(), claims.build());
        receipt.sign(new ECDSASigner(receiptKey));
        return receipt.serialize();
    }
}
