package com.vpbank.dcp.auth.application.port.out.repository;

import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.EnrollmentTransaction;
import java.util.Optional;

/**
 * Primary enrollments in flight (slice 11, Valkey): at most one per customer, channel and device, gone at its
 * {@code expiresAt}. Every write is compare-and-set on {@code version}. Every method throws
 * {@link RepositoryUnavailableException} when the store cannot answer; an uncertain write is reported as
 * unavailable, never as success.
 */
public interface EnrollmentTransactionStore {

    /** Stores a new transaction (version 0). False when the device already has one: nothing is overwritten. */
    boolean createIfAbsent(EnrollmentTransaction fresh);

    Optional<EnrollmentTransaction> find(CustomerId customerId, Channel channel, DeviceId deviceId);

    /**
     * Saves a changed transaction only if the stored version still equals {@code changed.version()}; returns
     * the stored transaction (version + 1). Empty = stale or gone.
     */
    Optional<EnrollmentTransaction> saveIfCurrent(EnrollmentTransaction changed);

    /**
     * Removes the transaction only if the stored version still equals {@code current.version()}. Of two racing
     * callers exactly one gets true: the one-shot that lets a single confirm commit the trust.
     */
    boolean deleteIfCurrent(EnrollmentTransaction current);
}
