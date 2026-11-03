package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.port.out.repository.EnrollmentTransactionStore;
import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.EnrollmentTransaction;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/** Test double with the store's contract: one transaction per device, compare-and-set on version, version + 1 per save. */
final class InMemoryEnrollmentTransactionStore implements EnrollmentTransactionStore {
    record Key(CustomerId customerId, Channel channel, DeviceId deviceId) {
    }

    final Map<Key, EnrollmentTransaction> rows = new HashMap<>();
    boolean unavailable;

    @Override
    public boolean createIfAbsent(EnrollmentTransaction fresh) {
        check();
        return rows.putIfAbsent(keyOf(fresh), fresh) == null;
    }

    @Override
    public Optional<EnrollmentTransaction> find(CustomerId customerId, Channel channel, DeviceId deviceId) {
        check();
        return Optional.ofNullable(rows.get(new Key(customerId, channel, deviceId)));
    }

    @Override
    public Optional<EnrollmentTransaction> saveIfCurrent(EnrollmentTransaction changed) {
        check();
        EnrollmentTransaction stored = rows.get(keyOf(changed));
        if (stored == null || stored.version() != changed.version()) {
            return Optional.empty();
        }
        EnrollmentTransaction saved = changed.withVersion(changed.version() + 1);
        rows.put(keyOf(changed), saved);
        return Optional.of(saved);
    }

    @Override
    public boolean deleteIfCurrent(EnrollmentTransaction current) {
        check();
        EnrollmentTransaction stored = rows.get(keyOf(current));
        if (stored == null || stored.version() != current.version()) {
            return false;
        }
        rows.remove(keyOf(current));
        return true;
    }

    EnrollmentTransaction only() {
        return rows.values().iterator().next();
    }

    private static Key keyOf(EnrollmentTransaction transaction) {
        return new Key(transaction.customerId(), transaction.channel(), transaction.deviceId());
    }

    private void check() {
        if (unavailable) {
            throw new RepositoryUnavailableException(new RuntimeException("down"));
        }
    }
}
