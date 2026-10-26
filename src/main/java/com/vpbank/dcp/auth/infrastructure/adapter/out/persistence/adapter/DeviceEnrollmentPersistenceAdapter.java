package com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.adapter;

import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.port.out.repository.EnrollmentRepository;
import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceEnrollment;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import com.vpbank.dcp.auth.domain.model.SessionId;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.common.DeviceIdProtection;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.entity.DeviceEnrollmentEntity;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.mapper.DeviceEnrollmentPersistenceMapper;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.DeviceEnrollmentJpaRepository;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.orm.ObjectOptimisticLockingFailureException;

/**
 * {@link EnrollmentRepository} over Spring Data JPA. The row never holds the app's device ID in clear,
 * only its HMAC lookup; the aggregate is rebuilt with the device ID the caller's session carries.
 */
@RequiredArgsConstructor
public class DeviceEnrollmentPersistenceAdapter implements EnrollmentRepository {
    @NonNull private final DeviceEnrollmentJpaRepository deviceEnrollmentJpaRepository;
    @NonNull private final DeviceIdProtection deviceIdProtection;

    @Override
    public DeviceEnrollment create(DeviceEnrollment freshEnrollment, SessionId sessionId) {
        DeviceEnrollmentEntity newEnrollmentEntity =
                DeviceEnrollmentPersistenceMapper.toEntity(freshEnrollment, sessionId, deviceIdProtection);
        try {
            DeviceEnrollmentEntity savedEnrollmentEntity = deviceEnrollmentJpaRepository.saveAndFlush(newEnrollmentEntity);
            return DeviceEnrollmentPersistenceMapper.toDomain(savedEnrollmentEntity, freshEnrollment.deviceId());
        } catch (DataIntegrityViolationException retried) {
            // UQ_DE_CREATION: the same restricted session already created an enrollment.
            try {
                return findCreatedBySession(freshEnrollment, sessionId)
                        .orElseThrow(() -> new RepositoryUnavailableException(retried));
            } catch (DataAccessException failure) {
                throw new RepositoryUnavailableException(failure);
            }
        } catch (DataAccessException failure) {
            throw new RepositoryUnavailableException(failure);
        }
    }

    private Optional<DeviceEnrollment> findCreatedBySession(DeviceEnrollment freshEnrollment, SessionId sessionId) {
        byte[] creationDigest = DeviceEnrollmentPersistenceMapper.creationDigest(sessionId);
        Optional<DeviceEnrollmentEntity> existingEnrollmentEntity = deviceEnrollmentJpaRepository
                .findByCustomerIdAndChannelAndPurposeAndCreationIdempotencyDigest(
                        freshEnrollment.customerId().value(),
                        freshEnrollment.channel().name(),
                        freshEnrollment.purpose(),
                        creationDigest);
        return existingEnrollmentEntity
                .map(entity -> DeviceEnrollmentPersistenceMapper.toDomain(entity, freshEnrollment.deviceId()));
    }

    @Override
    public Optional<DeviceEnrollment> find(EnrollmentId enrollmentId, CustomerId customerId, DeviceId deviceId) {
        try {
            Optional<DeviceEnrollmentEntity> enrollmentEntity =
                    deviceEnrollmentJpaRepository.findByIdAndCustomerId(enrollmentId.value(), customerId.value());
            if (enrollmentEntity.isEmpty()) {
                return Optional.empty();
            }

            // The row is only this device's when its stored lookup matches the device ID the session carries.
            boolean belongsToDevice = isTargetDevice(enrollmentEntity.get(), customerId, deviceId);
            if (!belongsToDevice) {
                return Optional.empty();
            }

            return Optional.of(DeviceEnrollmentPersistenceMapper.toDomain(enrollmentEntity.get(), deviceId));
        } catch (DataAccessException failure) {
            throw new RepositoryUnavailableException(failure);
        }
    }

    private boolean isTargetDevice(DeviceEnrollmentEntity enrollmentEntity, CustomerId customerId, DeviceId deviceId) {
        Channel channel = Channel.valueOf(enrollmentEntity.getChannel());
        byte[] expectedLookup = deviceIdProtection.lookup(
                enrollmentEntity.getClientDeviceIdLookupKeyId(),
                customerId,
                channel,
                deviceId);
        return MessageDigest.isEqual(enrollmentEntity.getTargetClientDeviceIdLookup(), expectedLookup);
    }

    @Override
    public Optional<DeviceEnrollment> findBySession(CustomerId customerId, DeviceId deviceId, SessionId sessionId) {
        throw new UnsupportedOperationException("slice 6 turn 2: approval lookups are not persisted yet");
    }

    @Override
    public Optional<DeviceEnrollment> findApproval(EnrollmentId enrollmentId, CustomerId customerId, Channel channel) {
        throw new UnsupportedOperationException("slice 6 turn 2: approval lookups are not persisted yet");
    }

    @Override
    public List<DeviceEnrollment> findOpenApprovals(CustomerId customerId, Channel channel) {
        throw new UnsupportedOperationException("slice 6 turn 2: approval lookups are not persisted yet");
    }

    @Override
    public Optional<DeviceEnrollment> saveIfCurrent(DeviceEnrollment changedEnrollment) {
        try {
            Optional<DeviceEnrollmentEntity> currentEnrollmentEntity =
                    deviceEnrollmentJpaRepository.findById(changedEnrollment.id().value());
            if (currentEnrollmentEntity.isEmpty()) {
                return Optional.empty();
            }
            DeviceEnrollmentEntity enrollmentEntity = currentEnrollmentEntity.get();

            boolean isCurrentVersion = enrollmentEntity.getVersion() == changedEnrollment.version();
            if (!isCurrentVersion) {
                return Optional.empty();
            }

            // Only the confirmed-trust transaction records the MFA confirmation time.
            Instant noMfaConfirmedAt = null;
            DeviceEnrollmentPersistenceMapper.apply(enrollmentEntity, changedEnrollment, noMfaConfirmedAt);

            DeviceEnrollmentEntity savedEnrollmentEntity = deviceEnrollmentJpaRepository.saveAndFlush(enrollmentEntity);
            DeviceEnrollment savedEnrollment =
                    DeviceEnrollmentPersistenceMapper.toDomain(savedEnrollmentEntity, changedEnrollment.deviceId());
            return Optional.of(savedEnrollment);
        } catch (ObjectOptimisticLockingFailureException stale) {
            return Optional.empty();
        } catch (DataAccessException failure) {
            throw new RepositoryUnavailableException(failure);
        }
    }
}
