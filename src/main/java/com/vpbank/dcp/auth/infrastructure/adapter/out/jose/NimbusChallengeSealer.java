package com.vpbank.dcp.auth.infrastructure.adapter.out.jose;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.vpbank.dcp.auth.application.port.out.exception.InvalidEncryptionKeyException;
import com.vpbank.dcp.auth.application.port.out.gateway.ChallengeSealer;
import com.vpbank.dcp.auth.application.port.out.model.OpenedChallenge;
import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import java.security.SecureRandom;
import java.text.ParseException;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/**
 * DD 20 §6a: challenge to the device as compact JWE ECDH-ES/A256GCM, {@code typ=trusted-device-challenge+jwe},
 * {@code kid} = device key thumbprint; the device answers with the same algorithms to Ksrv,
 * {@code typ=trusted-device-challenge-response+jwe}. Payload {@code {enrollmentId, challenge(base64url)}}.
 */
@RequiredArgsConstructor
public final class NimbusChallengeSealer implements ChallengeSealer {
    static final JOSEObjectType CHALLENGE_TYPE = new JOSEObjectType("trusted-device-challenge+jwe");
    static final JOSEObjectType RESPONSE_TYPE = new JOSEObjectType("trusted-device-challenge-response+jwe");
    private static final int CHALLENGE_BYTES = 32;
    private static final String PAYLOAD_ENROLLMENT_ID = "enrollmentId";
    private static final String PAYLOAD_CHALLENGE = "challenge";

    @NonNull private final SecureRandom secureRandom;

    @Override
    public byte[] newChallenge() {
        byte[] challenge = new byte[CHALLENGE_BYTES];
        secureRandom.nextBytes(challenge);
        return challenge;
    }

    @Override
    public String sealChallenge(String devicePublicJwk, EnrollmentId enrollmentId, byte[] challenge) {
        ECKey deviceKey = publicP256(devicePublicJwk);
        try {
            JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM)
                    .type(CHALLENGE_TYPE)
                    .keyID(deviceKey.computeThumbprint().toString())
                    .build();
            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put(PAYLOAD_ENROLLMENT_ID, enrollmentId.value().toString());
            payload.put(PAYLOAD_CHALLENGE, Base64.getUrlEncoder().withoutPadding().encodeToString(challenge));
            JWEObject jwe = new JWEObject(header, new Payload(payload));
            jwe.encrypt(new ECDHEncrypter(deviceKey));
            return jwe.serialize();
        } catch (JOSEException failure) {
            throw new IllegalStateException("Challenge could not be sealed", failure);
        }
    }

    @Override
    public Optional<OpenedChallenge> openResponse(String serverPrivateJwk, String challengeResponse) {
        try {
            ECKey serverKey = (ECKey) JWK.parse(serverPrivateJwk);
            JWEObject jwe = JWEObject.parse(challengeResponse);

            JWEHeader header = jwe.getHeader();
            boolean expectedType = RESPONSE_TYPE.equals(header.getType());
            boolean expectedAlgorithms = JWEAlgorithm.ECDH_ES.equals(header.getAlgorithm())
                    && EncryptionMethod.A256GCM.equals(header.getEncryptionMethod());
            if (!expectedType || !expectedAlgorithms) {
                return Optional.empty();
            }

            jwe.decrypt(new ECDHDecrypter(serverKey));

            Map<String, Object> payload = jwe.getPayload().toJSONObject();
            if (payload == null) {
                return Optional.empty();
            }
            if (!(payload.get(PAYLOAD_ENROLLMENT_ID) instanceof String enrollmentIdText)) {
                return Optional.empty();
            }
            if (!(payload.get(PAYLOAD_CHALLENGE) instanceof String challengeBase64)) {
                return Optional.empty();
            }

            EnrollmentId enrollmentId = new EnrollmentId(UUID.fromString(enrollmentIdText));
            byte[] challenge = Base64.getUrlDecoder().decode(challengeBase64);
            return Optional.of(new OpenedChallenge(enrollmentId, challenge));
        } catch (ParseException | JOSEException | IllegalArgumentException | ClassCastException invalid) {
            return Optional.empty();
        }
    }

    private static ECKey publicP256(String devicePublicJwk) {
        JWK jwk;
        try {
            jwk = JWK.parse(devicePublicJwk);
        } catch (ParseException malformed) {
            throw new InvalidEncryptionKeyException("devicePublicJwk is not a JWK");
        }
        if (!KeyType.EC.equals(jwk.getKeyType())) {
            throw new InvalidEncryptionKeyException("devicePublicJwk must be an EC P-256 key");
        }
        ECKey ecKey = (ECKey) jwk;
        if (!Curve.P_256.equals(ecKey.getCurve())) {
            throw new InvalidEncryptionKeyException("devicePublicJwk must be an EC P-256 key");
        }
        if (ecKey.isPrivate()) {
            throw new InvalidEncryptionKeyException("devicePublicJwk must be a public key");
        }
        return ecKey;
    }
}
