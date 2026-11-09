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
 * ({@link EnrollmentTransactions}). A restricted session starts one enrollment: its repeated init gets the first
 * answer again; a later login of the same device starts over. Nothing is written to SQL.
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
            Optional<CacheTransaction<EnrollmentTransaction>> found =
                    enrollmentTransactions.findOfDevice(newDeviceSession);
            if (found.isEmpty()) {
                return startEnrollment(command);
            }
            CacheTransaction<EnrollmentTransaction> deviceTransaction = found.get();
            boolean startedByThisSession = deviceTransaction.payload().belongsTo(newDeviceSession);
            if (startedByThisSession) {
                return answerAgain(command, deviceTransaction);
            }
            return startOver(command, deviceTransaction);
        } catch (RepositoryUnavailableException failure) {
            return new InitEnrollmentResult.Unavailable();
        }
    }

    /**
     * This session already ran init: the app lost the first answer, or sent the request twice. It gets the same
     * enrollment, Ksrv, challenge and deadline again; nothing is written. A repeat naming another key or platform
     * is a different request and is refused.
     */
    private static InitEnrollmentResult answerAgain(InitEnrollmentCommand command,
                                                    CacheTransaction<EnrollmentTransaction> started) {
        if (!asksForTheSameKey(command, started.payload())) {
            return new InitEnrollmentResult.Conflict();
        }
        return keyExchangeAnswer(started);
    }

    /** A repeat may leave the key and the platform out; what it does send must be what the first init kept. */
    private static boolean asksForTheSameKey(InitEnrollmentCommand command, EnrollmentTransaction enrollment) {
        String sentPublicJwk = command.devicePublicJwk();
        DevicePlatform sentPlatform = command.platform();
        boolean sameKey = sentPublicJwk == null || sentPublicJwk.equals(enrollment.devicePublicJwk());
        boolean samePlatform = sentPlatform == null || sentPlatform == enrollment.platform();
        return sameKey && samePlatform;
    }

    /** An earlier login of this device left its transaction: it is removed and this login starts its own. */
    private InitEnrollmentResult startOver(InitEnrollmentCommand command,
                                           CacheTransaction<EnrollmentTransaction> earlierTransaction) {
        boolean removed = enrollmentTransactions.makeRoomFor(earlierTransaction);
        if (!removed) {
            return new InitEnrollmentResult.Conflict();
        }
        return startEnrollment(command);
    }

    /** Resolves the key to trust and starts the key exchange with it. */
    private InitEnrollmentResult startEnrollment(InitEnrollmentCommand command) {
        AdmittedSession newDeviceSession = command.admitted();
        Optional<KnownDeviceSummary> knownDevice = knownDeviceOf(newDeviceSession);
        Optional<DeviceKey> deviceKey = resolveDeviceKey(command, knownDevice);
        if (deviceKey.isEmpty()) {
            return new InitEnrollmentResult.DeviceKeyRequired();
        }
        return startKeyExchange(newDeviceSession, knownDevice, deviceKey.get());
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
                .sealedChallenge(challenge.get().sealed())
                .build();

        // A racing init of the same device got there first.
        Optional<CacheTransaction<EnrollmentTransaction>> opened =
                enrollmentTransactions.open(EnrollmentTransaction.keyExchange(start));
        if (opened.isEmpty()) {
            return new InitEnrollmentResult.Conflict();
        }
        return keyExchangeAnswer(opened.get());
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

    /**
     * What the app needs to answer: the enrollment, Ksrv, the sealed challenge and the enrollment deadline. Read
     * from the transaction, so the first init and its repeats answer the same.
     */
    private static InitEnrollmentResult keyExchangeAnswer(CacheTransaction<EnrollmentTransaction> transaction) {
        EnrollmentTransaction enrollment = transaction.payload();
        return new InitEnrollmentResult.KeyExchange(
                enrollment.id(),
                enrollment.serverPublicJwk(),
                enrollment.sealedChallenge(),
                transaction.expiresAt());
    }

    /** The challenge as init sends it: the transaction keeps its digest and the sealed JWE that goes to the app. */
    private record SealedChallenge(String digest, String sealed) {
    }
}
