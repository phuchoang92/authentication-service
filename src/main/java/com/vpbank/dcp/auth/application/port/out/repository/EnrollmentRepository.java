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
     * Under the customer lock, reuses an open request for the installation or the request already
     * created by this session. Applies the quota before inserting a new enrollment.
     */
    ApprovalReservation reserveApproval(DeviceEnrollment fresh, SessionId sessionId, int maxPending);

    sealed interface ApprovalReservation {
        record Reserved(DeviceEnrollment enrollment) implements ApprovalReservation { }

        record QuotaReached() implements ApprovalReservation { }
    }

    /** Compare-and-set on version; returns the stored row. Empty = stale. */
    Optional<DeviceEnrollment> saveIfCurrent(DeviceEnrollment changed);

    /**
     * The newest approval request of this device on the channel, in any state (slice 11: the request, the status
     * poll and the claim are bound to the device, not to the restricted session that made the request).
     */
    Optional<DeviceEnrollment> findLatestApproval(CustomerId customerId, Channel channel, DeviceId deviceId);

    /**
     * From the primary device's side: an approval enrollment of the customer on the channel.
     * The requester's device ID is recovered from the enrollment's own ciphertext.
     */
    Optional<DeviceEnrollment> findApproval(EnrollmentId id, CustomerId customerId, Channel channel);

    /** Slice 6: every approval enrollment still waiting (WAITING_APPROVAL or WAITING_AUTHORIZATION). */
    List<DeviceEnrollment> findOpenApprovals(CustomerId customerId, Channel channel);
}
