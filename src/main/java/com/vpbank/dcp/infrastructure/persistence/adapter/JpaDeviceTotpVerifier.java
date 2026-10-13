package com.vpbank.dcp.infrastructure.persistence.adapter;

import com.vpbank.dcp.core.port.out.totp.CheckDeviceTotp;
import com.vpbank.dcp.core.port.out.totp.DeviceTotpCheckResult;
import com.vpbank.dcp.core.port.out.totp.DeviceTotpUnavailableException;
import com.vpbank.dcp.core.port.out.totp.DeviceTotpVerifier;
import com.vpbank.dcp.core.domain.totp.TotpVerificationPolicy;
import com.vpbank.dcp.infrastructure.adapter.out.totp.TotpAlgorithm;
import com.vpbank.dcp.infrastructure.adapter.out.totp.InvalidTotpSecretException;
import com.vpbank.dcp.infrastructure.adapter.out.totp.ProtectedTotpSecret;
import com.vpbank.dcp.infrastructure.adapter.out.totp.TotpSecretCodec;
import com.vpbank.dcp.infrastructure.persistence.projection.DeviceTotpCredentialView;
import com.vpbank.dcp.infrastructure.persistence.repository.DeviceTotpPersistenceRepository;
import com.vpbank.dcp.infrastructure.persistence.repository.UnexpectedDeviceTotpStateException;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;
import org.springframework.dao.DataAccessException;
import org.springframework.transaction.support.TransactionTemplate;

/** Verifies one code and consumes its time step in the same short SQL transaction. */
public final class JpaDeviceTotpVerifier implements DeviceTotpVerifier {
    private final DeviceTotpPersistenceRepository credentials;
    private final TotpSecretCodec codec;
    private final TotpAlgorithm algorithm;
    private final TotpVerificationPolicy policy;
    private final Clock clock;
    private final TransactionTemplate transactions;

    public JpaDeviceTotpVerifier(DeviceTotpPersistenceRepository credentials,
                                 TotpSecretCodec codec, TotpAlgorithm algorithm,
                                 TotpVerificationPolicy policy, Clock clock,
                                 TransactionTemplate transactions) {
        this.credentials = Objects.requireNonNull(credentials, "credentials");
        this.codec = Objects.requireNonNull(codec, "codec");
        this.algorithm = Objects.requireNonNull(algorithm, "algorithm");
        this.policy = Objects.requireNonNull(policy, "policy");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.transactions = Objects.requireNonNull(transactions, "transactions");
    }

    @Override
    public DeviceTotpCheckResult verify(CheckDeviceTotp command) {
        Objects.requireNonNull(command, "command");
        try {
            return Objects.requireNonNull(transactions.execute(ignored -> verifyLocked(command)));
        } catch (DataAccessException | IllegalStateException | InvalidTotpSecretException failure) {
            throw new DeviceTotpUnavailableException(failure);
        }
    }

    private DeviceTotpCheckResult verifyLocked(CheckDeviceTotp command) {
        if (!credentials.lockActiveDevice(command)) {
            return DeviceTotpCheckResult.REJECTED;
        }
        DeviceTotpCredentialView stored = credentials.lockActiveCredential(command.bindingId());
        if (stored == null) {
            return DeviceTotpCheckResult.REJECTED;
        }
        Instant now = clock.instant();
        if (stored.blockedUntil() != null && now.isBefore(stored.blockedUntil())) {
            return DeviceTotpCheckResult.REJECTED;
        }
        byte[] secret = codec.reveal(command.owner().customerId(), command.owner().channel(),
                command.bindingId(), stored.id(),
                new ProtectedTotpSecret(stored.secretKeyId(), stored.secretCiphertext()));
        try {
            long matchedStep = algorithm.matchingStep(secret, command.code(), now);
            if (matchedStep < 0 || matchedStep <= stored.lastAcceptedStep()) {
                recordFailure(command, stored, now);
                return DeviceTotpCheckResult.REJECTED;
            }
            if (!credentials.consumeStep(command.bindingId(), stored.id(), matchedStep,
                    stored.version())) {
                throw new UnexpectedDeviceTotpStateException();
            }
            return DeviceTotpCheckResult.ACCEPTED;
        } finally {
            Arrays.fill(secret, (byte) 0);
        }
    }

    private void recordFailure(CheckDeviceTotp command, DeviceTotpCredentialView stored, Instant now) {
        int usedAttempts = stored.blockedUntil() == null ? stored.failedAttempts() : 0;
        int nextAttempts = usedAttempts + 1;
        Instant blockedUntil = null;
        if (nextAttempts >= policy.maximumFailures()) {
            nextAttempts = 0;
            blockedUntil = now.plus(policy.lockDuration());
        }
        if (!credentials.recordFailure(command.bindingId(), stored.id(), stored.version(),
                nextAttempts, blockedUntil)) {
            throw new UnexpectedDeviceTotpStateException();
        }
    }
}
