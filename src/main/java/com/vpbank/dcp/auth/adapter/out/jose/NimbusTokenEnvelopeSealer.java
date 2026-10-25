package com.vpbank.dcp.auth.adapter.out.jose;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.vpbank.dcp.auth.adapter.out.jose.dto.TokenEnvelopePayload;
import com.vpbank.dcp.auth.application.port.out.InvalidEncryptionKeyException;
import com.vpbank.dcp.auth.application.port.out.TokenEnvelopeSealer;
import com.vpbank.dcp.auth.domain.model.OpaqueToken;
import com.vpbank.dcp.auth.domain.model.Session;

import java.text.ParseException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Compact JWE {@code ECDH-ES} / {@code A256GCM} to the app's public P-256 key (DD 06). Header:
 * {@code typ=BANKING_TOKEN}, {@code ver=1}, {@code kid} = the recipient key's RFC 7638 thumbprint,
 * so a different Kenc or an altered envelope fails on the app side. Only public EC P-256 keys are
 * accepted; a JWK carrying private members is refused.
 */
public final class NimbusTokenEnvelopeSealer implements TokenEnvelopeSealer {
    static final JOSEObjectType TYPE = new JOSEObjectType("BANKING_TOKEN");
    static final String VERSION_HEADER = "ver";

    @Override
    public String seal(String recipientPublicJwk, OpaqueToken token, Session session) {
        ECKey recipient = recipientKey(recipientPublicJwk);
        TokenEnvelopePayload payload = new TokenEnvelopePayload(token.value(), session.status().name(),
                session.customerId().value(), session.idleExpiresAt(), session.absoluteExpiresAt());
        try {
            JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM)
                    .type(TYPE).keyID(recipient.computeThumbprint().toString())
                    .customParam(VERSION_HEADER, 1).build();
            JWEObject jwe = new JWEObject(header, new Payload(json(payload)));
            jwe.encrypt(new ECDHEncrypter(recipient));
            return jwe.serialize();
        } catch (JOSEException failure) {
            throw new IllegalStateException("Token envelope could not be sealed", failure);
        }
    }

    /** Fixed member order; ISO-8601 UTC instants. Nimbus renders the map as JSON. */
    private static Map<String, Object> json(TokenEnvelopePayload payload) {
        Map<String, Object> json = new LinkedHashMap<>();
        json.put("token", payload.token());
        json.put("status", payload.status());
        json.put("customerId", payload.customerId());
        json.put("idleExpiresAt", payload.idleExpiresAt().toString());
        json.put("absoluteExpiresAt", payload.absoluteExpiresAt().toString());
        return json;
    }

    private static ECKey recipientKey(String json) {
        JWK jwk;
        try {
            jwk = JWK.parse(json);
        } catch (ParseException malformed) {
            throw new InvalidEncryptionKeyException("tokenEncryptionKey is not a JWK");
        }
        if (!KeyType.EC.equals(jwk.getKeyType())) {
            throw new InvalidEncryptionKeyException("tokenEncryptionKey must be an EC key");
        }
        ECKey key = (ECKey) jwk;
        if (!Curve.P_256.equals(key.getCurve())) {
            throw new InvalidEncryptionKeyException("tokenEncryptionKey must use P-256");
        }
        if (key.isPrivate()) {
            throw new InvalidEncryptionKeyException("tokenEncryptionKey must be a public key");
        }
        return key;
    }
}
