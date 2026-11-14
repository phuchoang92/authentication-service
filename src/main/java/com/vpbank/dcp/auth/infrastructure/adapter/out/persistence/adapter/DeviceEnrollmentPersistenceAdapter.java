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
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.entity.TrustedDeviceAuditEntity;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.mapper.DeviceEnrollmentPersistenceMapper;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.mapper.TrustedDevicePersistenceMapper;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.DeviceEnrollmentJpaRepository;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.TrustedDeviceAuditJpaRepository;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.CustomerAuthenticationJpaRepository;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataAccessException;
import org.springframework.orm.ObjectOptimisticLockingFailureException;
import org.springframework.transaction.annotation.Transactional;

/**
 * {@link EnrollmentRepository} over Spring Data JPA. Approval candidates and their protected
 * installation IDs are kept with the enrollment.
 */
@RequiredArgsConstructor
public class DeviceEnrollmentPersistenceAdapter implements EnrollmentRepository {
    private static final String EVENT_REGISTERED = "DEVICE_REGISTERED";
    private static final String AUDIT_CAUSE_LOGIN = "LOGIN";
    private static final String AUDIT_REASON_APPROVAL_REQUESTED = "APPROVAL_REQUESTED";
    private static final List<EnrollmentState> WAITING_STATES =
            List.of(EnrollmentState.WAITING_APPROVAL, EnrollmentState.WAITING_AUTHORIZATION);

    @NonNull private final DeviceEnrollmentJpaRepository deviceEnrollmentJpaRepository;
    @NonNull private final CustomerAuthenticationJpaRepository customerAuthenticationJpaRepository;
    @NonNull private final TrustedDeviceAuditJpaRepository trustedDeviceAuditJpaRepository;
    @NonNull private final DeviceIdProtection deviceIdProtection;
    @NonNull private final Clock clock;

    @Override
    @Transactional
    public ApprovalReservation reserveApproval(DeviceEnrollment freshEnrollment, SessionId sessionId, int maxPending) {
        try {
            String customerId = freshEnrollment.customerId().value();
            String channel = freshEnrollment.channel().name();
            if (customerAuthenticationJpaRepository.findByCustomerId(customerId).isEmpty()) {
                throw new RepositoryUnavailableException(new IllegalStateException("Approval owner is missing"));
            }
            Instant now = clock.instant();
            Optional<DeviceEnrollment> existingRequest = findLatestApproval(
                    freshEnrollment.customerId(), freshEnrollment.channel(), freshEnrollment.deviceId());
            if (existingRequest.isPresent() && existingRequest.get().isOpen(now)) {
                return new ApprovalReservation.Reserved(existingRequest.get());
            }
            Optional<DeviceEnrollment> requestFromSession = findCreatedBySession(freshEnrollment, sessionId);
            if (requestFromSession.isPresent()) {
                return new ApprovalReservation.Reserved(requestFromSession.get());
            }
            long waiting = deviceEnrollmentJpaRepository.countByCustomerIdAndChannelAndPurposeAndStateInAndExpiresAtAfter(
                    customerId, channel, EnrollmentPurpose.TRUST_DEVICE_APPROVAL, WAITING_STATES, now);
            if (waiting >= maxPending) {
                return new ApprovalReservation.QuotaReached();
            }
            DeviceEnrollmentEntity newEnrollmentEntity =
                    DeviceEnrollmentPersistenceMapper.toEntity(freshEnrollment, sessionId, deviceIdProtection);
            DeviceEnrollmentEntity savedEnrollmentEntity = deviceEnrollmentJpaRepository.saveAndFlush(newEnrollmentEntity);
            String correlationId = sessionId.toString();
            int sequence = trustedDeviceAuditJpaRepository.countByCorrelationId(correlationId);
            TrustedDeviceAuditEntity registrationAudit = TrustedDevicePersistenceMapper.toAudit(
                    savedEnrollmentEntity.getTargetDeviceId(), customerId, channel, null,
                    correlationId, sequence, EVENT_REGISTERED, AUDIT_CAUSE_LOGIN, AUDIT_REASON_APPROVAL_REQUESTED,
                    now, savedEnrollmentEntity.getId(), null);
            trustedDeviceAuditJpaRepository.saveAndFlush(registrationAudit);
            DeviceEnrollment savedRequest =
                    DeviceEnrollmentPersistenceMapper.toDomain(savedEnrollmentEntity, freshEnrollment.deviceId());
            return new ApprovalReservation.Reserved(savedRequest);
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

    /**
     * The approval row keeps the requesting device only as its HMAC lookup, so the lookup is computed with the
     * current lookup key and matched exactly. A request written under a lookup key that has since been rotated out
     * is not found; requests live a day at most (slice 11).
     */
    @Override
    public Optional<DeviceEnrollment> findLatestApproval(CustomerId customerId, Channel channel, DeviceId deviceId) {
        try {
            byte[] requesterLookup = deviceIdProtection.lookup(customerId, channel, deviceId);
            Optional<DeviceEnrollmentEntity> latestEntity = deviceEnrollmentJpaRepository
                    .findFirstByCustomerIdAndChannelAndPurposeAndRequesterClientDeviceIdLookupOrderByCreatedAtDesc(
                            customerId.value(),
                            channel.name(),
                            EnrollmentPurpose.TRUST_DEVICE_APPROVAL,
                            requesterLookup);
            return latestEntity.map(entity -> DeviceEnrollmentPersistenceMapper.toDomain(entity, deviceId));
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
                // An unreadable requester is left out of the approval list.
                withRequesterDeviceId(waitingEntity).ifPresent(approvals::add);
            }
            return List.copyOf(approvals);
        } catch (DataAccessException failure) {
            throw new RepositoryUnavailableException(failure);
        }
    }

    /**
     * From the primary device's side the requester ID is recovered from the enrollment itself.
     */
    private Optional<DeviceEnrollment> withRequesterDeviceId(DeviceEnrollmentEntity enrollmentEntity) {
        CustomerId customerId = new CustomerId(enrollmentEntity.getCustomerId());
        Channel channel = Channel.valueOf(enrollmentEntity.getChannel());
        Optional<DeviceId> requesterDeviceId = deviceIdProtection.decrypt(
                enrollmentEntity.getRequesterClientDeviceIdKeyId(),
                enrollmentEntity.getRequesterClientDeviceIdCiphertext(),
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
