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
import com.vpbank.dcp.infrastructure.persistence.entity.DeviceCredentialEntity;
import com.vpbank.dcp.infrastructure.persistence.repository.DeviceCredentialJpaRepository;
import com.vpbank.dcp.infrastructure.persistence.repository.DeviceTotpPersistenceRepository;
import com.vpbank.dcp.infrastructure.persistence.repository.UnexpectedDeviceTotpStateException;
import jakarta.persistence.PersistenceException;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import org.springframework.dao.DataAccessException;
import org.springframework.transaction.support.TransactionTemplate;

/** Verifies one code and consumes its time step in the same short SQL transaction. */
public final class JpaDeviceTotpVerifier implements DeviceTotpVerifier {
    private final DeviceTotpPersistenceRepository credentials;
    private final DeviceCredentialJpaRepository credentialRows;
    private final TotpSecretCodec codec;
    private final TotpAlgorithm algorithm;
    private final TotpVerificationPolicy policy;
    private final Clock clock;
    private final TransactionTemplate transactions;

    public JpaDeviceTotpVerifier(DeviceTotpPersistenceRepository credentials,
                                 DeviceCredentialJpaRepository credentialRows,
                                 TotpSecretCodec codec, TotpAlgorithm algorithm,
                                 TotpVerificationPolicy policy, Clock clock,
                                 TransactionTemplate transactions) {
        this.credentials = Objects.requireNonNull(credentials, "credentials");
        this.credentialRows = Objects.requireNonNull(credentialRows, "credentialRows");
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
        } catch (DataAccessException | PersistenceException | IllegalStateException
                 | InvalidTotpSecretException failure) {
            throw new DeviceTotpUnavailableException(failure);
        }
    }

    private DeviceTotpCheckResult verifyLocked(CheckDeviceTotp command) {
        if (!credentials.lockActiveDevice(command)) {
            return DeviceTotpCheckResult.REJECTED;
        }
        List<DeviceCredentialEntity> current = credentialRows.lockActive(command.bindingId());
        if (current.isEmpty()) {
            return DeviceTotpCheckResult.REJECTED;
        }
        if (current.size() != 1) {
            throw new UnexpectedDeviceTotpStateException();
        }
        DeviceCredentialEntity stored = current.getFirst();
        Instant now = clock.instant();
        Instant blockedUntil = stored.blockedUntil();
        if (blockedUntil != null && now.isBefore(blockedUntil)) {
            return DeviceTotpCheckResult.REJECTED;
        }
        if (stored.version() >= 9007199254740991L) {
            throw new UnexpectedDeviceTotpStateException();
        }
        byte[] secret = codec.reveal(command.owner().customerId(), command.owner().channel(),
                command.bindingId(), stored.id(),
                new ProtectedTotpSecret(stored.secretKeyId(), stored.secretCiphertext()));
        try {
            long matchedStep = algorithm.matchingStep(secret, command.code(), now);
            if (matchedStep < 0 || matchedStep <= stored.lastAcceptedStep()) {
                recordFailure(stored, now);
                return DeviceTotpCheckResult.REJECTED;
            }
            stored.acceptStep(matchedStep);
            credentialRows.flush();
            return DeviceTotpCheckResult.ACCEPTED;
        } finally {
            Arrays.fill(secret, (byte) 0);
        }
    }

    private void recordFailure(DeviceCredentialEntity stored, Instant now) {
        int usedAttempts = stored.blockedUntil() == null ? stored.failedAttempts() : 0;
        int nextAttempts = usedAttempts + 1;
        Instant blockedUntil = null;
        if (nextAttempts >= policy.maximumFailures()) {
            nextAttempts = 0;
            blockedUntil = now.plus(policy.lockDuration());
        }
        stored.recordFailure(nextAttempts, blockedUntil);
        credentialRows.flush();
    }
}
