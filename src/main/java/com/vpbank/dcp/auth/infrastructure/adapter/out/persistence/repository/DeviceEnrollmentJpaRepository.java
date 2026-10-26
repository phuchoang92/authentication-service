package com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository;

import com.vpbank.dcp.auth.domain.enums.EnrollmentPurpose;
import com.vpbank.dcp.auth.domain.enums.EnrollmentState;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.entity.DeviceEnrollmentEntity;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface DeviceEnrollmentJpaRepository extends JpaRepository<DeviceEnrollmentEntity, UUID> {

    /**
     * The row a retried create would collide with (UQ_DE_CREATION).
     */
    Optional<DeviceEnrollmentEntity> findByCustomerIdAndChannelAndPurposeAndCreationIdempotencyDigest(
            String customerId, String channel, EnrollmentPurpose purpose, byte[] creationIdempotencyDigest);

    Optional<DeviceEnrollmentEntity> findByIdAndCustomerId(UUID id, String customerId);

    /** The enrollment a restricted session created for one purpose (slice 6: the claim binding). */
    Optional<DeviceEnrollmentEntity> findByCustomerIdAndPurposeAndCreationIdempotencyDigest(
            String customerId, EnrollmentPurpose purpose, byte[] creationIdempotencyDigest);

    Optional<DeviceEnrollmentEntity> findByIdAndCustomerIdAndChannelAndPurpose(UUID id, String customerId, String channel,
                                                                                EnrollmentPurpose purpose);

    /** The approval requests still waiting on a customer's channel (slice 6: the primary device's list). */
    List<DeviceEnrollmentEntity> findByCustomerIdAndChannelAndPurposeAndStateInOrderByCreatedAtAsc(
            String customerId, String channel, EnrollmentPurpose purpose, Collection<EnrollmentState> states);
}
