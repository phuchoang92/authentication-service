package com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.adapter;

import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.port.out.model.TrustConfirmation;
import com.vpbank.dcp.auth.application.port.out.repository.TrustedDeviceRepository;
import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.DeviceStatus;
import com.vpbank.dcp.auth.domain.enums.EnrollmentState;
import com.vpbank.dcp.auth.domain.enums.PrimaryMode;
import com.vpbank.dcp.auth.domain.enums.TrustLevel;
import com.vpbank.dcp.auth.domain.model.*;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.common.DeviceIdProtection;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.entity.DeviceEnrollmentEntity;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.entity.PrimaryTrustedDeviceEntity;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.entity.TrustedDeviceAuditEntity;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.entity.TrustedDeviceEntity;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.mapper.DeviceEnrollmentPersistenceMapper;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.mapper.TrustedDevicePersistenceMapper;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.CustomerAuthenticationJpaRepository;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.DeviceEnrollmentJpaRepository;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.PrimaryTrustedDeviceJpaRepository;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.TrustedDeviceAuditJpaRepository;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.TrustedDeviceJpaRepository;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.interceptor.TransactionAspectSupport;

import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/** MySQL bindings, primary pointer and the atomic trust commit. */
@RequiredArgsConstructor
public class TrustedDevicePersistenceAdapter implements TrustedDeviceRepository {
    static final String EVENT_TRUSTED = "DEVICE_TRUSTED";
    static final String EVENT_EXPIRED = "DEVICE_EXPIRED";
    static final String EVENT_REPLACED = "DEVICE_REPLACED";
    static final String EVENT_PRIMARY_CHANGED = "PRIMARY_CHANGED";

    private static final String AUDIT_CAUSE_LOGIN = "LOGIN";
    private static final String AUDIT_CAUSE_POLICY = "POLICY";
    private static final String AUDIT_REASON_REINSTALL = "REINSTALL";
    private static final String AUDIT_REASON_TRUST_EXPIRED = "TRUST_EXPIRED";
    private static final String AUDIT_REASON_DEVICE_CAP = "DEVICE_CAP";
    private static final String AUDIT_REASON_MFA_FACE = "MFA_FACE";
    private static final String AUDIT_REASON_OLD_DEVICE_APPROVAL = "OLD_DEVICE_APPROVAL";

    @NonNull private final TrustedDeviceJpaRepository trustedDeviceJpaRepository;
    @NonNull private final PrimaryTrustedDeviceJpaRepository primaryTrustedDeviceJpaRepository;
    @NonNull private final TrustedDeviceAuditJpaRepository trustedDeviceAuditJpaRepository;
    @NonNull private final DeviceEnrollmentJpaRepository deviceEnrollmentJpaRepository;
    @NonNull private final CustomerAuthenticationJpaRepository customerAuthenticationJpaRepository;
    @NonNull private final DeviceIdProtection deviceIdProtection;
    @NonNull private final DevicePolicy devicePolicy;
    @NonNull private final Clock clock;

    @Override
    public Optional<TrustedDevice> findLive(CustomerId customerId, Channel channel, DeviceId deviceId) {
        byte[] deviceIdLookup = deviceIdProtection.lookup(customerId, channel, deviceId);
        return translate(() -> trustedDeviceJpaRepository
                .findByCustomerIdAndChannelAndClientDeviceIdLookup(
                        customerId.value(),
                        channel.name(),
                        deviceIdLookup)
                .flatMap(entity -> TrustedDevicePersistenceMapper.toDomain(entity, deviceIdProtection)));
    }

    @Override
    public List<TrustedDevice> findLive(CustomerId customerId, Channel channel) {
        return translate(() -> trustedDeviceJpaRepository
                .findByCustomerIdAndChannelOrderByCreatedAtAsc(customerId.value(), channel.name())
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

    @Override
    public Optional<TrustedDevice> findLivePrimary(DeviceInstallation installation) {
        byte[] deviceIdLookup = deviceIdProtection.lookup(
                installation.customerId(), installation.channel(), installation.deviceId());
        return translate(() -> trustedDeviceJpaRepository.findLivePrimary(
                        installation.customerId().value(),
                        installation.channel().name(),
                        deviceIdLookup)
                .flatMap(entity -> TrustedDevicePersistenceMapper.toDomain(entity, deviceIdProtection)));
    }

    @Override
    @Transactional
    public boolean recordLoginIfCurrent(TrustedDeviceId trustedDeviceId, long expectedVersion, Instant loggedInAt) {
        Instant updatedAt = clock.instant();
        int updatedRows = translate(() -> trustedDeviceJpaRepository.updateLastLoginIfCurrent(
                trustedDeviceId.value(),
                expectedVersion,
                loggedInAt,
                updatedAt,
                DeviceStatus.ACTIVE,
                TrustLevel.TRUSTED));
        return updatedRows == 1;
    }

    /**
     * Trust, binding retirement, the primary pointer, enrollment and audit share one transaction.
     * The owner lock also serializes cap decisions and revoke, including when there is no primary row yet.
     */
    @Override
    @Transactional
    public Optional<TrustedDevice> trustConfirmed(TrustConfirmation confirmation, String correlationId) {
        try {
            return commitTrust(confirmation, correlationId);
        } catch (OptimisticLockingFailureException stale) {
            TransactionAspectSupport.currentTransactionStatus().setRollbackOnly();
            return Optional.empty();
        } catch (DataAccessException failure) {
            throw new RepositoryUnavailableException(failure);
        }
    }

    private Optional<TrustedDevice> commitTrust(TrustConfirmation confirmation, String correlationId) {
        DeviceEnrollment enrollment = confirmation.enrollment();
        TrustedDevice confirmedDevice = confirmation.device();
        if (!enrollment.customerId().equals(confirmedDevice.customerId())
                || enrollment.channel() != confirmedDevice.channel()
                || !enrollment.deviceId().equals(confirmedDevice.deviceId())) {
            return Optional.empty();
        }
        String customerId = enrollment.customerId().value();
        String channel = enrollment.channel().name();
        if (customerAuthenticationJpaRepository.findByCustomerId(customerId).isEmpty()) {
            return Optional.empty();
        }

        boolean approval = enrollment.isApproval();
        boolean directEnrollment = confirmation.creationSessionId() != null;
        if (enrollment.state() != EnrollmentState.COMPLETED || approval == directEnrollment) {
            return Optional.empty();
        }
        Optional<DeviceEnrollmentEntity> existingEnrollment = deviceEnrollmentJpaRepository.findByIdAndCustomerIdAndChannel(
                enrollment.id().value(), customerId, channel);

        PrimaryTrustedDeviceEntity.Key primaryKey = new PrimaryTrustedDeviceEntity.Key(customerId, channel);
        Optional<PrimaryTrustedDeviceEntity> storedPrimary = primaryTrustedDeviceJpaRepository.findByKey(primaryKey);
        List<TrustedDeviceEntity> bindingRows = trustedDeviceJpaRepository.findByCustomerIdAndChannelOrderById(customerId, channel);
        Instant now = clock.instant();
        if (!enrollment.expiresAt().isAfter(now)
                || !canCompleteEnrollment(confirmation, existingEnrollment, storedPrimary, bindingRows, now)) {
            return Optional.empty();
        }

        byte[] installationLookup = deviceIdProtection.lookup(
                enrollment.customerId(), enrollment.channel(), enrollment.deviceId());
        Optional<TrustedDeviceEntity> currentBindingRow = bindingRows.stream()
                .filter(binding -> Arrays.equals(binding.getClientDeviceIdLookup(), installationLookup))
                .findFirst();
        UUID currentBindingId = currentBindingRow.map(TrustedDeviceEntity::getId).orElse(null);
        UUID expectedBindingId = enrollment.targetDeviceId() == null ? null : enrollment.targetDeviceId().value();
        if (!Objects.equals(currentBindingId, expectedBindingId)) {
            return Optional.empty();
        }

        List<TrustedDevice> currentBindings = bindingRows.stream().map(this::readBindingForWrite).toList();
        Optional<TrustedDevice> currentBinding = currentBindings.stream()
                .filter(binding -> binding.id().value().equals(currentBindingId))
                .findFirst();
        List<TrustedDevice> otherBindings = currentBindings.stream()
                .filter(binding -> !binding.id().value().equals(currentBindingId))
                .toList();
        List<TrustedDevice> retiredByCap = devicePolicy.bindingsBeyondCap(otherBindings);

        boolean renewExisting = approval && currentBinding
                .filter(binding -> !binding.hasExpired(now) && Objects.equals(binding.publicKey(), confirmedDevice.publicKey()))
                .isPresent();
        int sequence = trustedDeviceAuditJpaRepository.countByCorrelationId(correlationId);
        if (currentBinding.isPresent() && !renewExisting) {
            TrustedDevice replacedBinding = currentBinding.get();
            deleteBinding(replacedBinding);
            String reason = replacedBinding.hasExpired(now) ? AUDIT_REASON_TRUST_EXPIRED : AUDIT_REASON_REINSTALL;
            TrustedDeviceAuditEntity replacementAudit = TrustedDevicePersistenceMapper.toAudit(
                    replacedBinding, actorDeviceIdOf(confirmation), correlationId, sequence,
                    EVENT_REPLACED, AUDIT_CAUSE_LOGIN, reason, now, enrollment.id().value(), null);
            trustedDeviceAuditJpaRepository.save(replacementAudit);
            sequence++;
        }

        for (TrustedDevice retiredBinding : retiredByCap) {
            deleteBinding(retiredBinding);
            TrustedDeviceAuditEntity expiryAudit = TrustedDevicePersistenceMapper.toAudit(
                    retiredBinding, actorDeviceIdOf(confirmation), correlationId, sequence,
                    EVENT_EXPIRED, AUDIT_CAUSE_POLICY, AUDIT_REASON_DEVICE_CAP, now, enrollment.id().value(), null);
            trustedDeviceAuditJpaRepository.save(expiryAudit);
            sequence++;
        }

        TrustedDevice savedBinding = saveTrustedBinding(confirmedDevice, currentBindingRow, renewExisting, now);
        PrimaryTrustedDeviceEntity primary = storedPrimary
                .orElseGet(() -> TrustedDevicePersistenceMapper.toPrimary(savedBinding, now));
        primary.assign(savedBinding.id().value(), now, enrollment.id().value(),
                confirmation.faceAuthenticated(), confirmation.primaryMode());
        primaryTrustedDeviceJpaRepository.saveAndFlush(primary);

        DeviceEnrollmentEntity completedEnrollment = existingEnrollment.orElseGet(() ->
                DeviceEnrollmentPersistenceMapper.toEntity(enrollment, confirmation.creationSessionId(), deviceIdProtection));
        DeviceEnrollmentPersistenceMapper.apply(completedEnrollment, enrollment, now);
        deviceEnrollmentJpaRepository.saveAndFlush(completedEnrollment);

        recordTrustAudit(confirmation, savedBinding, correlationId, sequence, now);
        return Optional.of(savedBinding);
    }

    private boolean canCompleteEnrollment(TrustConfirmation confirmation,
                                          Optional<DeviceEnrollmentEntity> existingEnrollment,
                                          Optional<PrimaryTrustedDeviceEntity> primary,
                                          List<TrustedDeviceEntity> bindings,
                                          Instant now) {
        if (confirmation.creationSessionId() != null) {
            return existingEnrollment.isEmpty();
        }

        DeviceEnrollment completed = confirmation.enrollment();
        if (existingEnrollment.isEmpty() || primary.isEmpty() || completed.actorDeviceId() == null) {
            return false;
        }

        DeviceEnrollmentEntity stored = existingEnrollment.get();
        DeviceEnrollment waiting = DeviceEnrollmentPersistenceMapper.toDomain(stored, completed.deviceId());
        UUID actorId = completed.actorDeviceId().value();
        byte[] requesterLookup = deviceIdProtection.lookup(completed.customerId(), completed.channel(), completed.deviceId());
        return waiting.isApproval()
                && waiting.isAuthorized()
                && waiting.isOpen(now)
                && !waiting.authorizationExpired(now)
                && waiting.version() == completed.version()
                && Objects.equals(waiting.targetDeviceId(), completed.targetDeviceId())
                && Objects.equals(waiting.candidateKey(), completed.candidateKey())
                && waiting.candidateKey() != null
                && waiting.candidateKey().publicJwk().equals(confirmation.device().publicKey())
                && waiting.candidateKey().platform() == confirmation.device().platform()
                && Objects.equals(waiting.authorizationTokenDigest(), completed.authorizationTokenDigest())
                && Objects.equals(waiting.actorDeviceId(), completed.actorDeviceId())
                && Objects.equals(waiting.actorDeviceId(), confirmation.actorDeviceId())
                && Arrays.equals(stored.getRequesterClientDeviceIdLookup(), requesterLookup)
                && actorId.equals(primary.get().getPrimaryDeviceId())
                && bindings.stream()
                        .filter(binding -> actorId.equals(binding.getId()))
                        .anyMatch(binding -> binding.getStatus() == DeviceStatus.ACTIVE
                                && binding.getTrustLevel() == TrustLevel.TRUSTED
                                && now.isBefore(binding.getExpiresAt()));
    }

    private void deleteBinding(TrustedDevice binding) {
        int deleted = trustedDeviceJpaRepository.deleteIfCurrent(binding.id().value(), binding.version());
        if (deleted != 1) {
            throw new OptimisticLockingFailureException("The device binding changed during trust confirmation");
        }
    }

    private TrustedDevice saveTrustedBinding(TrustedDevice candidate,
                                             Optional<TrustedDeviceEntity> currentBinding,
                                             boolean renewExisting,
                                             Instant now) {
        if (renewExisting) {
            TrustedDeviceEntity currentRow = currentBinding.orElseThrow();
            TrustedDevice renewed = readBindingForWrite(currentRow).trustByApproval(now, devicePolicy);
            TrustedDevicePersistenceMapper.apply(currentRow, renewed);
            return readBindingForWrite(trustedDeviceJpaRepository.saveAndFlush(currentRow));
        }
        TrustedDeviceEntity newBindingRow = TrustedDevicePersistenceMapper.toEntity(candidate, deviceIdProtection);
        return readBindingForWrite(trustedDeviceJpaRepository.saveAndFlush(newBindingRow));
    }

    private TrustedDevice readBindingForWrite(TrustedDeviceEntity row) {
        return TrustedDevicePersistenceMapper.toDomain(row, deviceIdProtection)
                .orElseThrow(() -> new RepositoryUnavailableException(new IllegalStateException("Unreadable device binding")));
    }

    private void recordTrustAudit(TrustConfirmation confirmation,
                                  TrustedDevice savedBinding,
                                  String correlationId,
                                  int sequence,
                                  Instant now) {
        UUID enrollmentId = confirmation.enrollment().id().value();
        UUID actorId = confirmation.actorDeviceId() == null ? savedBinding.id().value() : confirmation.actorDeviceId().value();
        String trustReason = trustReasonOf(confirmation);
        TrustedDeviceAuditEntity trustAudit = TrustedDevicePersistenceMapper.toAudit(
                savedBinding, actorId, correlationId, sequence, EVENT_TRUSTED, AUDIT_CAUSE_LOGIN,
                trustReason, now, enrollmentId, trustMetadataOf(confirmation));
        trustedDeviceAuditJpaRepository.save(trustAudit);

        TrustedDeviceAuditEntity primaryAudit = TrustedDevicePersistenceMapper.toAudit(
                savedBinding, actorId, correlationId, sequence + 1, EVENT_PRIMARY_CHANGED, AUDIT_CAUSE_LOGIN,
                trustReason, now, enrollmentId, null);
        trustedDeviceAuditJpaRepository.saveAndFlush(primaryAudit);
    }

    /**
     * The device itself passed FACE (slice 5), or the primary device approved it (slice 6).
     */
    private static String trustReasonOf(TrustConfirmation confirmation) {
        if (confirmation.primaryMode() == PrimaryMode.OLD_DEVICE_APPROVAL) {
            return AUDIT_REASON_OLD_DEVICE_APPROVAL;
        }
        return AUDIT_REASON_MFA_FACE;
    }

    /**
     * The trust event records what proved it: the receipt digest, or the approving device.
     */
    private static String trustMetadataOf(TrustConfirmation confirmation) {
        if (confirmation.receiptDigest() != null) {
            return "{\"receiptDigest\":\"" + confirmation.receiptDigest() + "\"}";
        }
        if (confirmation.actorDeviceId() != null) {
            return "{\"approvedBy\":\"" + confirmation.actorDeviceId().value() + "\"}";
        }
        return null;
    }

    /**
     * The approving primary device when there is one; otherwise the trusted device acted for itself.
     */
    private static UUID actorDeviceIdOf(TrustConfirmation confirmation) {
        if (confirmation.actorDeviceId() != null) {
            return confirmation.actorDeviceId().value();
        }
        return confirmation.device().id().value();
    }

    private static <T> T translate(Supplier<T> repositoryCall) {
        try {
            return repositoryCall.get();
        } catch (DataAccessException failure) {
            throw new RepositoryUnavailableException(failure);
        }
    }
}
