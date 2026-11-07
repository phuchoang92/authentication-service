package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.command.InitEnrollmentCommand;
import com.vpbank.dcp.auth.application.port.in.InitEnrollmentUseCase;
import com.vpbank.dcp.auth.application.port.out.exception.InvalidEncryptionKeyException;
import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.port.out.gateway.ChallengeSealer;
import com.vpbank.dcp.auth.application.port.out.gateway.ServerKeyPairGenerator;
import com.vpbank.dcp.auth.application.port.out.model.CacheTransaction;
import com.vpbank.dcp.auth.application.port.out.model.ServerKeyPair;
import com.vpbank.dcp.auth.application.result.InitEnrollmentResult;
import com.vpbank.dcp.auth.application.result.KnownDeviceSummary;
import com.vpbank.dcp.auth.domain.enums.DevicePlatform;
import com.vpbank.dcp.auth.domain.model.AdmittedSession;
import com.vpbank.dcp.auth.domain.model.DeviceKey;
import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import com.vpbank.dcp.auth.domain.model.EnrollmentTransaction;
import com.vpbank.dcp.auth.domain.model.KeyExchangeStart;
import com.vpbank.dcp.auth.domain.model.TrustedDeviceId;
import java.util.Optional;
import java.util.function.Supplier;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/**
 * Step 1 of a new device trusting itself from its restricted session (DD 20 §4): hands the app the server key
 * (Ksrv) and a challenge sealed to the device key, and opens the device's enrollment transaction
 * ({@link EnrollmentTransactions}). Runs once per restricted session; a later login of the same device starts over.
 * Nothing is written to SQL.
 */
@RequiredArgsConstructor
public final class InitEnrollmentService implements InitEnrollmentUseCase {
    @NonNull
    private final EnrollmentTransactions enrollmentTransactions;
    @NonNull
    private final TrustedDeviceService trustedDeviceService;
    @NonNull
    private final ServerKeyPairGenerator serverKeyPairGenerator;
    @NonNull
    private final ChallengeSealer challengeSealer;
    @NonNull
    private final Supplier<EnrollmentId> enrollmentIdGenerator;

    @Override
    public InitEnrollmentResult init(InitEnrollmentCommand command) {
        AdmittedSession newDeviceSession = command.admitted();
        if (!newDeviceSession.restricted()) {
            return new InitEnrollmentResult.Conflict();
        }
        try {
            // init runs once per restricted session; a new login on the same device starts over.
            if (!enrollmentTransactions.makeRoomFor(newDeviceSession)) {
                return new InitEnrollmentResult.Conflict();
            }
            Optional<KnownDeviceSummary> knownDevice = knownDeviceOf(newDeviceSession);
            Optional<DeviceKey> deviceKey = resolveDeviceKey(command, knownDevice);
            if (deviceKey.isEmpty()) {
                return new InitEnrollmentResult.DeviceKeyRequired();
            }
            return startKeyExchange(newDeviceSession, knownDevice, deviceKey.get());
        } catch (RepositoryUnavailableException failure) {
            return new InitEnrollmentResult.Unavailable();
        }
    }

    private Optional<KnownDeviceSummary> knownDeviceOf(AdmittedSession newDeviceSession) {
        return trustedDeviceService.knownDevice(
                newDeviceSession.customerId(),
                newDeviceSession.channel(),
                newDeviceSession.deviceId());
    }

    /** The key to trust: what the device sends now, else what Auth keeps for a known device; a new device sends both. */
    private static Optional<DeviceKey> resolveDeviceKey(InitEnrollmentCommand command,
                                                        Optional<KnownDeviceSummary> knownDevice) {
        String publicJwk = command.devicePublicJwk();
        if (publicJwk == null && knownDevice.isPresent()) {
            publicJwk = knownDevice.get().publicKey();
        }
        DevicePlatform platform = command.platform();
        if (platform == null && knownDevice.isPresent()) {
            platform = knownDevice.get().platform();
        }
        if (publicJwk == null || platform == null) {
            return Optional.empty();
        }
        return Optional.of(new DeviceKey(publicJwk, platform));
    }

    /** Challenges the device to prove its key, opens the transaction and answers with Ksrv and the sealed challenge. */
    private InitEnrollmentResult startKeyExchange(AdmittedSession newDeviceSession,
                                                  Optional<KnownDeviceSummary> knownDevice,
                                                  DeviceKey deviceKey) {
        EnrollmentId enrollmentId = enrollmentIdGenerator.get();
        Optional<SealedChallenge> challenge = challengeDevice(deviceKey, enrollmentId);
        if (challenge.isEmpty()) {
            return new InitEnrollmentResult.DeviceKeyRequired();
        }

        ServerKeyPair serverKeyPair = serverKeyPairGenerator.next();
        TrustedDeviceId targetDeviceId = knownDevice.map(KnownDeviceSummary::id).orElse(null);
        KeyExchangeStart start = KeyExchangeStart.builder()
                .enrollmentId(enrollmentId)
                .newDeviceSession(newDeviceSession)
                .targetDeviceId(targetDeviceId)
                .deviceKey(deviceKey)
                .serverPublicJwk(serverKeyPair.publicJwk())
                .serverPrivateJwk(serverKeyPair.privateJwk())
                .challengeDigest(challenge.get().digest())
                .build();

        // A racing init of the same device got there first.
        Optional<CacheTransaction<EnrollmentTransaction>> opened =
                enrollmentTransactions.open(EnrollmentTransaction.keyExchange(start));
        if (opened.isEmpty()) {
            return new InitEnrollmentResult.Conflict();
        }
        return keyExchangeAnswer(start, challenge.get(), opened.get());
    }

    /** A fresh challenge sealed to the device key; empty when that key cannot encrypt. */
    private Optional<SealedChallenge> challengeDevice(DeviceKey deviceKey, EnrollmentId enrollmentId) {
        byte[] challenge = challengeSealer.newChallenge();
        try {
            String sealed = challengeSealer.sealChallenge(deviceKey.publicJwk(), enrollmentId, challenge);
            return Optional.of(new SealedChallenge(EnrollmentDigests.digest(challenge), sealed));
        } catch (InvalidEncryptionKeyException badKey) {
            return Optional.empty();
        }
    }

    /** What the app needs to answer: the enrollment, Ksrv, the sealed challenge and the enrollment deadline. */
    private static InitEnrollmentResult keyExchangeAnswer(KeyExchangeStart start,
                                                          SealedChallenge challenge,
                                                          CacheTransaction<EnrollmentTransaction> opened) {
        return new InitEnrollmentResult.KeyExchange(
                start.enrollmentId(),
                start.serverPublicJwk(),
                challenge.sealed(),
                opened.expiresAt());
    }

    /** The challenge as init sends it: its digest is kept in the transaction, the sealed JWE goes to the app. */
    private record SealedChallenge(String digest, String sealed) {
    }
}
