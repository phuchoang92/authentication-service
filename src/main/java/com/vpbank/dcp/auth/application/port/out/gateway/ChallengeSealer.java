package com.vpbank.dcp.auth.application.port.out.gateway;

import com.vpbank.dcp.auth.application.port.out.exception.InvalidEncryptionKeyException;
import com.vpbank.dcp.auth.application.port.out.model.OpenedChallenge;
import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import java.util.Optional;

/**
 * The key-exchange crypto of DD 20 §4/§6a: a random challenge sealed to the device's public key
 * (compact JWE, ECDH-ES/A256GCM), and the device's answer opened with Ksrv's private key.
 */
public interface ChallengeSealer {
    /** 32 random bytes. */
    byte[] newChallenge();

    /** Throws {@link InvalidEncryptionKeyException} when the device key is not a usable public P-256 JWK. */
    String sealChallenge(String devicePublicJwk, EnrollmentId enrollmentId, byte[] challenge);

    /** Empty when the response cannot be opened with this Ksrv or is not the expected shape. */
    Optional<OpenedChallenge> openResponse(String serverPrivateJwk, String challengeResponse);
}
