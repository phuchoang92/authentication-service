package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.port.out.model.CacheTransaction;
import com.vpbank.dcp.auth.application.port.out.model.TransactionKind;
import com.vpbank.dcp.auth.application.port.out.repository.TransactionStore;
import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.EnrollmentState;
import com.vpbank.dcp.auth.domain.model.AdmittedSession;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.EnrollmentTransaction;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/**
 * The primary enrollment's view of the shared {@link TransactionStore} (slice 11). A device has at most one
 * transaction, started by one restricted session and open for the lifetime of that session. The services ask
 * for what the flow needs; the transaction kind, its address and the envelope version stay here.
 */
@RequiredArgsConstructor
public final class EnrollmentTransactions {
    private static final TransactionKind<EnrollmentTransaction> KIND =
            new TransactionKind<>("enrollment", EnrollmentTransaction.class);

    @NonNull
    private final TransactionStore transactionStore;
    /** How long a transaction may wait for confirm: the lifetime of the restricted session that runs it. */
    @NonNull
    private final Duration lifetime;
    @NonNull
    private final Clock clock;

    /** This restricted session has already started the primary enrollment of its device. */
    public boolean wasStartedBy(AdmittedSession newDeviceSession) {
        Optional<CacheTransaction<EnrollmentTransaction>> deviceTransaction = findOfDevice(newDeviceSession);
        return deviceTransaction.isPresent() && deviceTransaction.get().payload().belongsTo(newDeviceSession);
    }

    /**
     * Clears the way for this restricted session to start: the transaction an earlier login of the same device
     * left is removed. False when this session already started one, or another request changed it first.
     */
    public boolean makeRoomFor(AdmittedSession newDeviceSession) {
        Optional<CacheTransaction<EnrollmentTransaction>> earlierTransaction = findOfDevice(newDeviceSession);
        if (earlierTransaction.isEmpty()) {
            return true;
        }
        if (earlierTransaction.get().payload().belongsTo(newDeviceSession)) {
            return false;
        }
        return transactionStore.deleteIfCurrent(earlierTransaction.get());
    }

    /** Opens the transaction init started; empty when a racing init of the same device got there first. */
    public Optional<CacheTransaction<EnrollmentTransaction>> open(EnrollmentTransaction keyExchange) {
        String deviceAddress = addressOf(keyExchange.channel(), keyExchange.customerId(), keyExchange.deviceId());
        Instant expiresAt = clock.instant().plus(lifetime);
        CacheTransaction<EnrollmentTransaction> freshTransaction = KIND.open(deviceAddress, expiresAt, keyExchange);

        boolean created = transactionStore.createIfAbsent(freshTransaction);
        if (!created) {
            return Optional.empty();
        }
        return Optional.of(freshTransaction);
    }

    /** The device's transaction, when this restricted session started it, it is still open and it waits at this step. */
    public Optional<CacheTransaction<EnrollmentTransaction>> findOpenAt(AdmittedSession newDeviceSession,
                                                                        EnrollmentState step) {
        Optional<CacheTransaction<EnrollmentTransaction>> deviceTransaction = findOfDevice(newDeviceSession);
        if (deviceTransaction.isEmpty()) {
            return Optional.empty();
        }
        CacheTransaction<EnrollmentTransaction> transaction = deviceTransaction.get();
        boolean waitsForThisSession = transaction.payload().belongsTo(newDeviceSession)
                && transaction.isOpen(clock.instant())
                && transaction.payload().state() == step;
        if (!waitsForThisSession) {
            return Optional.empty();
        }
        return deviceTransaction;
    }

    /** Writes the changed enrollment over the version read; empty when another request changed it first. */
    public Optional<CacheTransaction<EnrollmentTransaction>> update(CacheTransaction<EnrollmentTransaction> transaction,
                                                                    EnrollmentTransaction changedEnrollment) {
        return transactionStore.saveIfCurrent(transaction, changedEnrollment);
    }

    /** Takes the transaction for the one confirm that commits; false when another request changed it first. */
    public boolean claim(CacheTransaction<EnrollmentTransaction> transaction) {
        return transactionStore.deleteIfCurrent(transaction);
    }

    /** Drops a failed or expired enrollment; a transaction another request already changed is left to it. */
    public void remove(CacheTransaction<EnrollmentTransaction> transaction) {
        transactionStore.deleteIfCurrent(transaction);
    }

    private Optional<CacheTransaction<EnrollmentTransaction>> findOfDevice(AdmittedSession newDeviceSession) {
        String deviceAddress = addressOf(
                newDeviceSession.channel(),
                newDeviceSession.customerId(),
                newDeviceSession.deviceId());
        return transactionStore.find(KIND, deviceAddress);
    }

    /** One transaction per device, whichever login started it: {@code <channel>:<customerId>:<deviceId>}. */
    private static String addressOf(Channel channel, CustomerId customerId, DeviceId deviceId) {
        return channel.name() + ":" + customerId.value() + ":" + deviceId.value();
    }
}
