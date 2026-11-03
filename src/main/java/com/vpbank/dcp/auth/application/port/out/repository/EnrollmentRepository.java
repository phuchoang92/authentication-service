package com.vpbank.dcp.auth.application.port.out.repository;

import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceEnrollment;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import com.vpbank.dcp.auth.domain.model.SessionId;
import java.util.List;
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

    /**
     * The newest approval request of this device on the channel, in any state (slice 11: the request, the status
     * poll and the claim are bound to the device, not to the restricted session that made the request).
     */
    Optional<DeviceEnrollment> findLatestApproval(CustomerId customerId, Channel channel, DeviceId deviceId);

    /**
     * Slice 6, from the primary device's side: an approval enrollment of the customer on the channel. The
     * requester's device ID is recovered from the target device row; an enrollment whose target cannot be
     * read is absent.
     */
    Optional<DeviceEnrollment> findApproval(EnrollmentId id, CustomerId customerId, Channel channel);

    /** Slice 6: every approval enrollment still waiting (WAITING_APPROVAL or WAITING_AUTHORIZATION). */
    List<DeviceEnrollment> findOpenApprovals(CustomerId customerId, Channel channel);
}
