package com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.adapter;

import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.port.out.repository.EnrollmentRepository;
import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.EnrollmentPurpose;
import com.vpbank.dcp.auth.domain.enums.EnrollmentState;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceEnrollment;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import com.vpbank.dcp.auth.domain.model.SessionId;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.common.DeviceIdProtection;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.entity.DeviceEnrollmentEntity;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.entity.TrustedDeviceEntity;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.mapper.DeviceEnrollmentPersistenceMapper;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.DeviceEnrollmentJpaRepository;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.TrustedDeviceJpaRepository;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
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
    private static final List<EnrollmentState> WAITING_STATES =
            List.of(EnrollmentState.WAITING_APPROVAL, EnrollmentState.WAITING_AUTHORIZATION);

    @NonNull private final DeviceEnrollmentJpaRepository deviceEnrollmentJpaRepository;
    @NonNull private final TrustedDeviceJpaRepository trustedDeviceJpaRepository;
    @NonNull private final DeviceIdProtection deviceIdProtection;
    @NonNull private final Clock clock;

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
        try {
            byte[] creationDigest = DeviceEnrollmentPersistenceMapper.creationDigest(sessionId);
            Optional<DeviceEnrollmentEntity> enrollmentEntity = deviceEnrollmentJpaRepository
                    .findByCustomerIdAndPurposeAndCreationIdempotencyDigest(
                            customerId.value(),
                            EnrollmentPurpose.TRUST_DEVICE_APPROVAL,
                            creationDigest);
            if (enrollmentEntity.isEmpty()) {
                return Optional.empty();
            }

            boolean belongsToDevice = isTargetDevice(enrollmentEntity.get(), customerId, deviceId);
            if (!belongsToDevice) {
                return Optional.empty();
            }

            return Optional.of(DeviceEnrollmentPersistenceMapper.toDomain(enrollmentEntity.get(), deviceId));
        } catch (DataAccessException failure) {
            throw new RepositoryUnavailableException(failure);
        }
    }

    @Override
    public Optional<DeviceEnrollment> findApproval(EnrollmentId enrollmentId, CustomerId customerId, Channel channel) {
        try {
            Optional<DeviceEnrollmentEntity> enrollmentEntity = deviceEnrollmentJpaRepository
                    .findByIdAndCustomerIdAndChannelAndPurpose(
                            enrollmentId.value(),
                            customerId.value(),
                            channel.name(),
                            EnrollmentPurpose.TRUST_DEVICE_APPROVAL);
            if (enrollmentEntity.isEmpty()) {
                return Optional.empty();
            }
            return withRequesterDeviceId(enrollmentEntity.get());
        } catch (DataAccessException failure) {
            throw new RepositoryUnavailableException(failure);
        }
    }

    @Override
    public List<DeviceEnrollment> findOpenApprovals(CustomerId customerId, Channel channel) {
        try {
            List<DeviceEnrollmentEntity> waitingEntities = deviceEnrollmentJpaRepository
                    .findByCustomerIdAndChannelAndPurposeAndStateInOrderByCreatedAtAsc(
                            customerId.value(),
                            channel.name(),
                            EnrollmentPurpose.TRUST_DEVICE_APPROVAL,
                            WAITING_STATES);

            List<DeviceEnrollment> approvals = new ArrayList<>();
            for (DeviceEnrollmentEntity waitingEntity : waitingEntities) {
                // a request whose target row cannot be read any more is not shown
                withRequesterDeviceId(waitingEntity).ifPresent(approvals::add);
            }
            return List.copyOf(approvals);
        } catch (DataAccessException failure) {
            throw new RepositoryUnavailableException(failure);
        }
    }

    /**
     * From the primary device's side the requester's device ID is not in the request: it is recovered from
     * the target device row's ciphertext. An unreadable or missing target makes the request absent.
     */
    private Optional<DeviceEnrollment> withRequesterDeviceId(DeviceEnrollmentEntity enrollmentEntity) {
        if (enrollmentEntity.getTargetDeviceId() == null) {
            return Optional.empty();
        }
        Optional<TrustedDeviceEntity> targetEntity = trustedDeviceJpaRepository.findById(enrollmentEntity.getTargetDeviceId());
        if (targetEntity.isEmpty()) {
            return Optional.empty();
        }

        CustomerId customerId = new CustomerId(enrollmentEntity.getCustomerId());
        Channel channel = Channel.valueOf(enrollmentEntity.getChannel());
        Optional<DeviceId> requesterDeviceId = deviceIdProtection.decrypt(
                targetEntity.get().getClientDeviceIdKeyId(),
                targetEntity.get().getClientDeviceIdCiphertext(),
                customerId,
                channel);

        return requesterDeviceId.map(deviceId -> DeviceEnrollmentPersistenceMapper.toDomain(enrollmentEntity, deviceId));
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

            // The FACE path records its MFA time in the trust transaction; the approval path when the token is issued.
            Instant mfaConfirmedAt = null;
            boolean approverPassedMfa = changedEnrollment.isApproval()
                    && changedEnrollment.state() == EnrollmentState.WAITING_AUTHORIZATION;
            if (approverPassedMfa) {
                mfaConfirmedAt = clock.instant();
            }
            DeviceEnrollmentPersistenceMapper.apply(enrollmentEntity, changedEnrollment, mfaConfirmedAt);

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
