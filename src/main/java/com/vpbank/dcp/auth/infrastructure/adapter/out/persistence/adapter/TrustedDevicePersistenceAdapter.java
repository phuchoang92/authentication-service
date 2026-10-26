package com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.adapter;

import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.port.out.model.TrustConfirmation;
import com.vpbank.dcp.auth.application.port.out.repository.TrustedDeviceRepository;
import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.DeviceStatus;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.TrustedDevice;
import com.vpbank.dcp.auth.domain.model.TrustedDeviceId;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.common.DeviceIdProtection;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.entity.DeviceEnrollmentEntity;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.entity.PrimaryTrustedDeviceEntity;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.entity.TrustedDeviceAuditEntity;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.entity.TrustedDeviceEntity;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.mapper.DeviceEnrollmentPersistenceMapper;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.mapper.TrustedDevicePersistenceMapper;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.DeviceEnrollmentJpaRepository;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.PrimaryTrustedDeviceJpaRepository;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.TrustedDeviceAuditJpaRepository;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.TrustedDeviceJpaRepository;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.orm.ObjectOptimisticLockingFailureException;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.interceptor.TransactionAspectSupport;

/**
 * {@link TrustedDeviceRepository} over Spring Data JPA. The database only stops races (one live
 * row per installation, one primary per customer + channel); the aggregate decided every rule.
 * {@link #trustFirstDevice} and {@link #trustConfirmed} are the multi-table transactions: device
 * rows, primary row, enrollment and audit events together, or nothing. Spring exceptions never
 * leave this class.
 */
@RequiredArgsConstructor
public class TrustedDevicePersistenceAdapter implements TrustedDeviceRepository {
    /** The LIVE_SLOT marker of a PENDING, ACTIVE or SUSPENDED row (NULL once expired or revoked). */
    private static final Byte LIVE = 1;

    static final String EVENT_TRUSTED = "DEVICE_TRUSTED";
    static final String EVENT_PRIMARY = "PRIMARY_ASSIGNED";
    static final String EVENT_LOGIN = "DEVICE_LOGIN";
    static final String EVENT_EXPIRED = "DEVICE_EXPIRED";
    static final String EVENT_REPLACED = "DEVICE_REPLACED";
    static final String EVENT_PRIMARY_CHANGED = "PRIMARY_CHANGED";

    private static final String AUDIT_CAUSE_LOGIN = "LOGIN";
    private static final String AUDIT_CAUSE_POLICY = "POLICY";
    private static final String AUDIT_REASON_FIRST_DEVICE = "FIRST_DEVICE";
    private static final String AUDIT_REASON_REINSTALL = "REINSTALL";
    private static final String AUDIT_REASON_DEVICE_CAP = "DEVICE_CAP";
    private static final String AUDIT_REASON_MFA_FACE = "MFA_FACE";

    @NonNull private final TrustedDeviceJpaRepository trustedDeviceJpaRepository;
    @NonNull private final PrimaryTrustedDeviceJpaRepository primaryTrustedDeviceJpaRepository;
    @NonNull private final TrustedDeviceAuditJpaRepository trustedDeviceAuditJpaRepository;
    @NonNull private final DeviceEnrollmentJpaRepository deviceEnrollmentJpaRepository;
    @NonNull private final DeviceIdProtection deviceIdProtection;
    @NonNull private final Clock clock;

    @Override
    public Optional<TrustedDevice> findLive(CustomerId customerId, Channel channel, DeviceId deviceId) {
        byte[] deviceIdLookup = deviceIdProtection.lookup(customerId, channel, deviceId);
        return translate(() -> trustedDeviceJpaRepository
                .findByCustomerIdAndChannelAndClientDeviceIdLookupAndLiveSlot(
                        customerId.value(),
                        channel.name(),
                        deviceIdLookup,
                        LIVE)
                .flatMap(entity -> TrustedDevicePersistenceMapper.toDomain(entity, deviceIdProtection)));
    }

    @Override
    public List<TrustedDevice> findLive(CustomerId customerId, Channel channel) {
        return translate(() -> trustedDeviceJpaRepository
                .findByCustomerIdAndChannelAndLiveSlotOrderByCreatedAtAsc(customerId.value(), channel.name(), LIVE)
                .stream()
                // a row whose device ID cannot be opened is "no device", not a guess
                .flatMap(entity -> TrustedDevicePersistenceMapper.toDomain(entity, deviceIdProtection).stream())
                .toList());
    }

    @Override
    public Optional<TrustedDeviceId> findPrimary(CustomerId customerId, Channel channel) {
        PrimaryTrustedDeviceEntity.Key primaryKey = new PrimaryTrustedDeviceEntity.Key(customerId.value(), channel.name());
        return translate(() -> primaryTrustedDeviceJpaRepository.findById(primaryKey)
                .map(PrimaryTrustedDeviceEntity::getPrimaryDeviceId)
                .map(TrustedDeviceId::new));
    }

    /**
     * Device row, primary row and audit 0..1 together. A lost race on a unique key marks the
     * transaction rollback-only and answers {@code AlreadyHasDevice}: nothing of this attempt stays.
     */
    @Override
    @Transactional
    public TrustFirstResult trustFirstDevice(TrustedDevice device, String correlationId) {
        Instant now = clock.instant();
        PrimaryTrustedDeviceEntity.Key primaryKey =
                new PrimaryTrustedDeviceEntity.Key(device.customerId().value(), device.channel().name());
        try {
            boolean customerAlreadyHasPrimary = primaryTrustedDeviceJpaRepository.existsById(primaryKey);
            if (customerAlreadyHasPrimary) {
                return new TrustFirstResult.AlreadyHasDevice();
            }

            TrustedDeviceEntity newDeviceEntity = TrustedDevicePersistenceMapper.toEntity(device, deviceIdProtection);
            TrustedDeviceEntity savedDeviceEntity = trustedDeviceJpaRepository.saveAndFlush(newDeviceEntity);

            PrimaryTrustedDeviceEntity primaryEntity = TrustedDevicePersistenceMapper.toPrimary(device, now);
            primaryTrustedDeviceJpaRepository.saveAndFlush(primaryEntity);

            int sequence = 0;
            TrustedDeviceAuditEntity trustedAudit = TrustedDevicePersistenceMapper.toAudit(
                    device,
                    correlationId,
                    sequence,
                    EVENT_TRUSTED,
                    AUDIT_CAUSE_LOGIN,
                    AUDIT_REASON_FIRST_DEVICE,
                    now);
            trustedDeviceAuditJpaRepository.save(trustedAudit);
            sequence++;

            TrustedDeviceAuditEntity primaryAudit = TrustedDevicePersistenceMapper.toAudit(
                    device,
                    correlationId,
                    sequence,
                    EVENT_PRIMARY,
                    AUDIT_CAUSE_LOGIN,
                    AUDIT_REASON_FIRST_DEVICE,
                    now);
            trustedDeviceAuditJpaRepository.saveAndFlush(primaryAudit);

            TrustedDevice trustedDevice = TrustedDevicePersistenceMapper.toDomain(savedDeviceEntity, deviceIdProtection)
                    .orElseThrow();
            return new TrustFirstResult.Trusted(trustedDevice);
        } catch (DataIntegrityViolationException raced) {
            // UQ_TD_LIVE_INSTALLATION or the primary's primary key: another login got there first.
            TransactionAspectSupport.currentTransactionStatus().setRollbackOnly();
            return new TrustFirstResult.AlreadyHasDevice();
        } catch (DataAccessException failure) {
            throw new RepositoryUnavailableException(failure);
        }
    }

    /**
     * The enrollment flow's commit, all or nothing: replaced/capped rows → EXPIRED, the new trusted row,
     * the primary row re-pointed (FACE_CONFIRMED, enrollment, face flag), the enrollment COMPLETED, and
     * the audit trail 0..n under the correlation ID with the enrollment ID and the MFA receipt digest.
     */
    @Override
    @Transactional
    public TrustedDevice trustConfirmed(TrustConfirmation confirmation, String correlationId) {
        Instant now = clock.instant();
        TrustedDevice newTrustedDevice = confirmation.device();
        UUID enrollmentId = confirmation.enrollment().id().value();
        // These audit events carry no extra metadata; only the trust event records the receipt digest.
        String noMetadata = null;
        try {
            int sequence = 0;

            TrustedDevice replacedDevice = confirmation.replaced();
            if (replacedDevice != null) {
                expireRow(replacedDevice);

                TrustedDeviceAuditEntity replacementAudit = TrustedDevicePersistenceMapper.toAudit(
                        replacedDevice,
                        correlationId,
                        sequence,
                        EVENT_REPLACED,
                        AUDIT_CAUSE_LOGIN,
                        AUDIT_REASON_REINSTALL,
                        now,
                        enrollmentId,
                        noMetadata);
                trustedDeviceAuditJpaRepository.save(replacementAudit);
                sequence++;
            }

            for (TrustedDevice cappedDevice : confirmation.expiredByCap()) {
                expireRow(cappedDevice);

                TrustedDeviceAuditEntity capAudit = TrustedDevicePersistenceMapper.toAudit(
                        cappedDevice,
                        correlationId,
                        sequence,
                        EVENT_EXPIRED,
                        AUDIT_CAUSE_POLICY,
                        AUDIT_REASON_DEVICE_CAP,
                        now,
                        enrollmentId,
                        noMetadata);
                trustedDeviceAuditJpaRepository.save(capAudit);
                sequence++;
            }

            TrustedDeviceEntity newDeviceEntity =
                    TrustedDevicePersistenceMapper.toEntity(newTrustedDevice, deviceIdProtection);
            TrustedDeviceEntity savedDeviceEntity = trustedDeviceJpaRepository.saveAndFlush(newDeviceEntity);

            PrimaryTrustedDeviceEntity.Key primaryKey = new PrimaryTrustedDeviceEntity.Key(
                    newTrustedDevice.customerId().value(),
                    newTrustedDevice.channel().name());
            PrimaryTrustedDeviceEntity primaryEntity = primaryTrustedDeviceJpaRepository.findById(primaryKey)
                    .orElseGet(() -> TrustedDevicePersistenceMapper.toPrimary(newTrustedDevice, now));
            primaryEntity.assign(
                    savedDeviceEntity.getId(),
                    now,
                    enrollmentId,
                    confirmation.faceAuthenticated(),
                    confirmation.primaryMode());
            primaryTrustedDeviceJpaRepository.saveAndFlush(primaryEntity);

            DeviceEnrollmentEntity enrollmentEntity = deviceEnrollmentJpaRepository.findById(enrollmentId).orElseThrow();
            DeviceEnrollmentPersistenceMapper.apply(enrollmentEntity, confirmation.enrollment(), now);
            deviceEnrollmentJpaRepository.saveAndFlush(enrollmentEntity);

            String receiptMetadataJson = "{\"receiptDigest\":\"" + confirmation.receiptDigest() + "\"}";
            TrustedDeviceAuditEntity trustedAudit = TrustedDevicePersistenceMapper.toAudit(
                    newTrustedDevice,
                    correlationId,
                    sequence,
                    EVENT_TRUSTED,
                    AUDIT_CAUSE_LOGIN,
                    AUDIT_REASON_MFA_FACE,
                    now,
                    enrollmentId,
                    receiptMetadataJson);
            trustedDeviceAuditJpaRepository.save(trustedAudit);
            sequence++;

            TrustedDeviceAuditEntity primaryChangedAudit = TrustedDevicePersistenceMapper.toAudit(
                    newTrustedDevice,
                    correlationId,
                    sequence,
                    EVENT_PRIMARY_CHANGED,
                    AUDIT_CAUSE_LOGIN,
                    AUDIT_REASON_MFA_FACE,
                    now,
                    enrollmentId,
                    noMetadata);
            trustedDeviceAuditJpaRepository.saveAndFlush(primaryChangedAudit);

            return TrustedDevicePersistenceMapper.toDomain(savedDeviceEntity, deviceIdProtection).orElseThrow();
        } catch (DataAccessException failure) {
            throw new RepositoryUnavailableException(failure); // a RuntimeException: the transaction rolls back
        }
    }

    @Override
    public TrustedDevice registerPending(TrustedDevice pendingDevice, String correlationId) {
        throw new UnsupportedOperationException("slice 6 turn 2: PENDING rows are not persisted yet");
    }

    @Override
    public int countPending(CustomerId customerId, Channel channel) {
        throw new UnsupportedOperationException("slice 6 turn 2: PENDING rows are not persisted yet");
    }

    private void expireRow(TrustedDevice expiredDevice) {
        TrustedDeviceEntity deviceEntity = trustedDeviceJpaRepository.findById(expiredDevice.id().value()).orElseThrow();
        TrustedDevicePersistenceMapper.apply(deviceEntity, expiredDevice);
        trustedDeviceJpaRepository.saveAndFlush(deviceEntity);
    }

    @Override
    public Optional<TrustedDevice> saveIfCurrent(TrustedDevice changedDevice, String correlationId) {
        try {
            Optional<TrustedDeviceEntity> currentDeviceEntity =
                    trustedDeviceJpaRepository.findById(changedDevice.id().value());
            if (currentDeviceEntity.isEmpty()) {
                return Optional.empty();
            }
            TrustedDeviceEntity deviceEntity = currentDeviceEntity.get();

            boolean isCurrentVersion = deviceEntity.getVersion() == changedDevice.version();
            if (!isCurrentVersion) {
                return Optional.empty();
            }

            // Decided before the row changes: only a live row that becomes EXPIRED gets an audit event.
            boolean expiringNow = changedDevice.status() == DeviceStatus.EXPIRED && deviceEntity.getStatus().live();

            TrustedDevicePersistenceMapper.apply(deviceEntity, changedDevice);
            TrustedDeviceEntity savedDeviceEntity = trustedDeviceJpaRepository.saveAndFlush(deviceEntity);

            if (expiringNow) {
                int firstEventSequence = 0;
                TrustedDeviceAuditEntity expiredAudit = TrustedDevicePersistenceMapper.toAudit(
                        changedDevice,
                        correlationId,
                        firstEventSequence,
                        EVENT_EXPIRED,
                        AUDIT_CAUSE_POLICY,
                        AUDIT_REASON_DEVICE_CAP,
                        clock.instant());
                trustedDeviceAuditJpaRepository.saveAndFlush(expiredAudit);
            }

            return TrustedDevicePersistenceMapper.toDomain(savedDeviceEntity, deviceIdProtection);
        } catch (ObjectOptimisticLockingFailureException stale) {
            return Optional.empty();
        } catch (DataAccessException failure) {
            throw new RepositoryUnavailableException(failure);
        }
    }

    private static <T> T translate(Supplier<T> repositoryCall) {
        try {
            return repositoryCall.get();
        } catch (DataAccessException failure) {
            throw new RepositoryUnavailableException(failure);
        }
    }
}
