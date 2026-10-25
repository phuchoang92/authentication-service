package com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository;

import com.vpbank.dcp.auth.domain.enums.EnrollmentPurpose;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.entity.DeviceEnrollmentEntity;
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
}
