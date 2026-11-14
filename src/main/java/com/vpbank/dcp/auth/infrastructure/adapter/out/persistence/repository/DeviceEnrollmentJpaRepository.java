package com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository;

import com.vpbank.dcp.auth.domain.enums.EnrollmentPurpose;
import com.vpbank.dcp.auth.domain.enums.EnrollmentState;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.entity.DeviceEnrollmentEntity;
import jakarta.persistence.LockModeType;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;

public interface DeviceEnrollmentJpaRepository extends JpaRepository<DeviceEnrollmentEntity, UUID> {

    /**
     * The row a retried create would collide with (UQ_DE_CREATION).
     */
    Optional<DeviceEnrollmentEntity> findByCustomerIdAndChannelAndPurposeAndCreationIdempotencyDigest(
            String customerId, String channel, EnrollmentPurpose purpose, byte[] creationIdempotencyDigest);

    Optional<DeviceEnrollmentEntity> findByIdAndCustomerId(UUID id, String customerId);

    /** The newest enrollment of one requesting device for one purpose (slice 11: the approval is bound to the device). */
    Optional<DeviceEnrollmentEntity> findFirstByCustomerIdAndChannelAndPurposeAndRequesterClientDeviceIdLookupOrderByCreatedAtDesc(
            String customerId, String channel, EnrollmentPurpose purpose, byte[] requesterClientDeviceIdLookup);

    Optional<DeviceEnrollmentEntity> findByIdAndCustomerIdAndChannelAndPurpose(UUID id, String customerId, String channel,
                                                                                EnrollmentPurpose purpose);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<DeviceEnrollmentEntity> findByIdAndCustomerIdAndChannel(UUID id, String customerId, String channel);

    long countByCustomerIdAndChannelAndPurposeAndStateInAndExpiresAtAfter(
            String customerId, String channel, EnrollmentPurpose purpose, Collection<EnrollmentState> states, Instant now);

    /** The approval requests still waiting on a customer's channel (slice 6: the primary device's list). */
    List<DeviceEnrollmentEntity> findByCustomerIdAndChannelAndPurposeAndStateInOrderByCreatedAtAsc(
            String customerId, String channel, EnrollmentPurpose purpose, Collection<EnrollmentState> states);
}
