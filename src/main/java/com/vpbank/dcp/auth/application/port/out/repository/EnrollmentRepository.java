package com.vpbank.dcp.auth.application.port.out.repository;

import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceEnrollment;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import com.vpbank.dcp.auth.domain.model.SessionId;
import java.util.Optional;

/** TRUSTED_DEVICE_ENROLLMENT (phase 4). Throws {@link RepositoryUnavailableException}. */
public interface EnrollmentRepository {

    /**
     * Stores a new enrollment, or returns the one already created from the same restricted
     * session (UQ_DE_CREATION): a retried init never makes a second enrollment.
     */
    DeviceEnrollment create(DeviceEnrollment fresh, SessionId sessionId);

    /** The row keeps only the device ID's lookup, so the caller's session supplies the ID; it must match. */
    Optional<DeviceEnrollment> find(EnrollmentId id, CustomerId customerId, DeviceId deviceId);

    /** Compare-and-set on version; returns the stored row. Empty = stale. */
    Optional<DeviceEnrollment> saveIfCurrent(DeviceEnrollment changed);
}
