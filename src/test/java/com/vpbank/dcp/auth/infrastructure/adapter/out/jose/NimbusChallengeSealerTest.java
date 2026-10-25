package com.vpbank.dcp.auth.infrastructure.adapter.out.jose;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.vpbank.dcp.auth.application.port.out.exception.InvalidEncryptionKeyException;
import com.vpbank.dcp.auth.application.port.out.model.OpenedChallenge;
import com.vpbank.dcp.auth.application.port.out.model.ServerKeyPair;
import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Plays the app: decrypt the challenge with the device key, re-encrypt it to Ksrv, and check Auth opens it. */
class NimbusChallengeSealerTest {
    private final NimbusChallengeSealer sealer = new NimbusChallengeSealer(new SecureRandom());
    private final NimbusServerKeyPairGenerator keys = new NimbusServerKeyPairGenerator();
    private final EnrollmentId enrollment = EnrollmentId.random();

    @Test
    void theDeviceCanReadTheChallengeAndAuthCanReadTheAnswer() throws Exception {
        ECKey device = new ECKeyGenerator(Curve.P_256).generate();
        ServerKeyPair ksrv = keys.next();
        byte[] challenge = sealer.newChallenge();
        assertThat(challenge).hasSize(32);
        assertThat(sealer.newChallenge()).isNotEqualTo(challenge);

        String sealed = sealer.sealChallenge(device.toPublicJWK().toJSONString(), enrollment, challenge);
        JWEObject jwe = JWEObject.parse(sealed);
        assertThat(jwe.getHeader().getType().getType()).isEqualTo("trusted-device-challenge+jwe");
        assertThat(jwe.getHeader().getKeyID()).isEqualTo(device.computeThumbprint().toString());
        jwe.decrypt(new ECDHDecrypter(device));
        Map<String, Object> payload = jwe.getPayload().toJSONObject();
        assertThat(payload.get("enrollmentId")).isEqualTo(enrollment.toString());
        assertThat(Base64.getUrlDecoder().decode((String) payload.get("challenge"))).isEqualTo(challenge);

        String answer = answer(ECKey.parse(ksrv.publicJwk()), enrollment.toString(), challenge, "trusted-device-challenge-response+jwe");
        OpenedChallenge opened = sealer.openResponse(ksrv.privateJwk(), answer).orElseThrow();
        assertThat(opened.enrollmentId()).isEqualTo(enrollment);
        assertThat(opened.challenge()).isEqualTo(challenge);
        assertThat(ksrv.toString()).doesNotContain("\"d\"");
    }

    @Test
    void anAnswerToAnotherKeyWrongTypeOrGarbageIsEmptyAndBadDeviceKeysAreRefused() throws Exception {
        ServerKeyPair ksrv = keys.next();
        ServerKeyPair other = keys.next();
        byte[] challenge = sealer.newChallenge();
        String toOther = answer(ECKey.parse(other.publicJwk()), enrollment.toString(), challenge, "trusted-device-challenge-response+jwe");
        assertThat(sealer.openResponse(ksrv.privateJwk(), toOther)).isEmpty();
        String wrongType = answer(ECKey.parse(ksrv.publicJwk()), enrollment.toString(), challenge, "trusted-device-challenge+jwe");
        assertThat(sealer.openResponse(ksrv.privateJwk(), wrongType)).isEmpty();
        assertThat(sealer.openResponse(ksrv.privateJwk(), "not.a.jwe")).isEmpty();

        ECKey p384 = new ECKeyGenerator(Curve.P_384).generate();
        assertThatThrownBy(() -> sealer.sealChallenge(p384.toPublicJWK().toJSONString(), enrollment, challenge))
                .isInstanceOf(InvalidEncryptionKeyException.class);
        ECKey withPrivate = new ECKeyGenerator(Curve.P_256).generate();
        assertThatThrownBy(() -> sealer.sealChallenge(withPrivate.toJSONString(), enrollment, challenge))
                .isInstanceOf(InvalidEncryptionKeyException.class);
        assertThatThrownBy(() -> sealer.sealChallenge("{}", enrollment, challenge)).isInstanceOf(InvalidEncryptionKeyException.class);
    }

    private static String answer(ECKey recipient, String enrollmentId, byte[] challenge, String type) throws Exception {
        JWEObject jwe = new JWEObject(new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM)
                .type(new com.nimbusds.jose.JOSEObjectType(type)).build(),
                new Payload(Map.of("enrollmentId", enrollmentId,
                        "challenge", Base64.getUrlEncoder().withoutPadding().encodeToString(challenge))));
        jwe.encrypt(new ECDHEncrypter(recipient));
        return jwe.serialize();
    }
}
