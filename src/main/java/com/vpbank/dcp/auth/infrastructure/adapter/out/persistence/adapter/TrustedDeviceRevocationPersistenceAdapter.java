package com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.adapter;

import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.port.out.model.DeviceRevocation;
import com.vpbank.dcp.auth.application.port.out.repository.TrustedDeviceRevocationStore;
import com.vpbank.dcp.auth.domain.enums.DeviceStatus;
import com.vpbank.dcp.auth.domain.enums.TrustLevel;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.entity.PrimaryTrustedDeviceEntity;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.entity.TrustedDeviceAuditEntity;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.entity.TrustedDeviceEntity;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.mapper.TrustedDevicePersistenceMapper;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.CustomerAuthenticationJpaRepository;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.PrimaryTrustedDeviceJpaRepository;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.TrustedDeviceAuditJpaRepository;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.TrustedDeviceJpaRepository;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.TrustedDeviceRevokeRepository;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import jakarta.persistence.PersistenceException;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataAccessException;
import org.springframework.transaction.annotation.Transactional;

/** Writes the revoked snapshot, removes the binding, and records the action in MySQL. */
@RequiredArgsConstructor
public class TrustedDeviceRevocationPersistenceAdapter implements TrustedDeviceRevocationStore {
    private static final String EVENT_REVOKED = "DEVICE_REVOKED";
    private static final String AUDIT_CAUSE_CUSTOMER = "USER";

    @NonNull private final CustomerAuthenticationJpaRepository customerAuthenticationJpaRepository;
    @NonNull private final PrimaryTrustedDeviceJpaRepository primaryTrustedDeviceJpaRepository;
    @NonNull private final TrustedDeviceJpaRepository trustedDeviceJpaRepository;
    @NonNull private final TrustedDeviceRevokeRepository trustedDeviceRevokeRepository;
    @NonNull private final TrustedDeviceAuditJpaRepository trustedDeviceAuditJpaRepository;
    @NonNull private final Clock clock;

    @Override
    @Transactional
    public RevocationCommit revoke(DeviceRevocation command) {
        try {
            return commitRevocation(command);
        } catch (DataAccessException | PersistenceException failure) {
            throw new RepositoryUnavailableException(failure);
        }
    }

    private RevocationCommit commitRevocation(DeviceRevocation command) {
        String customerId = command.customerId().value();
        String channel = command.channel().name();
        if (customerAuthenticationJpaRepository.findByCustomerId(customerId).isEmpty()) {
            return RevocationCommit.NOT_FOUND;
        }

        PrimaryTrustedDeviceEntity.Key primaryKey = new PrimaryTrustedDeviceEntity.Key(customerId, channel);
        Optional<PrimaryTrustedDeviceEntity> currentPrimary = primaryTrustedDeviceJpaRepository.findByKey(primaryKey);
        UUID actorId = command.primaryBindingId().value();
        UUID targetId = command.targetBindingId().value();
        Optional<TrustedDeviceEntity> target = trustedDeviceJpaRepository.findByIdAndCustomerIdAndChannel(
                targetId, customerId, channel);

        if (target.isEmpty()) {
            return trustedDeviceRevokeRepository.contains(command)
                    ? RevocationCommit.ALREADY_COMMITTED
                    : RevocationCommit.NOT_FOUND;
        }
        if (currentPrimary.isEmpty() || !actorId.equals(currentPrimary.get().getPrimaryDeviceId())) {
            return RevocationCommit.NOT_PRIMARY;
        }

        Optional<TrustedDeviceEntity> actor = trustedDeviceJpaRepository.findByIdAndCustomerIdAndChannel(
                actorId, customerId, channel);
        Instant now = clock.instant();
        if (actor.isEmpty() || !mayRevoke(actor.get(), now)) {
            return RevocationCommit.NOT_PRIMARY;
        }

        TrustedDeviceEntity binding = target.get();
        if (trustedDeviceRevokeRepository.snapshot(binding) != 1) {
            throw new RepositoryUnavailableException(new IllegalStateException("Binding snapshot was not written"));
        }
        boolean removedPrimary = targetId.equals(actorId);
        if (removedPrimary) {
            currentPrimary.get().clear();
            primaryTrustedDeviceJpaRepository.flush();
        }
        if (trustedDeviceJpaRepository.deleteIfCurrent(targetId, binding.getVersion()) != 1) {
            throw new RepositoryUnavailableException(new IllegalStateException("Binding was not removed"));
        }

        int sequence = trustedDeviceAuditJpaRepository.countByCorrelationId(command.correlationId());
        TrustedDeviceAuditEntity revokedAudit = TrustedDevicePersistenceMapper.toAudit(
                targetId, customerId, channel, actorId, command.correlationId(), sequence,
                EVENT_REVOKED, AUDIT_CAUSE_CUSTOMER, command.reasonCode(), now, null, null);
        trustedDeviceAuditJpaRepository.save(revokedAudit);
        if (removedPrimary) {
            TrustedDeviceAuditEntity primaryAudit = TrustedDevicePersistenceMapper.toAudit(
                    targetId, customerId, channel, actorId, command.correlationId(), sequence + 1,
                    TrustedDevicePersistenceAdapter.EVENT_PRIMARY_CHANGED, AUDIT_CAUSE_CUSTOMER,
                    command.reasonCode(), now, null, null);
            trustedDeviceAuditJpaRepository.save(primaryAudit);
        }
        trustedDeviceAuditJpaRepository.flush();
        return RevocationCommit.COMMITTED;
    }

    private static boolean mayRevoke(TrustedDeviceEntity actor, Instant now) {
        return actor.getStatus() == DeviceStatus.ACTIVE
                && actor.getTrustLevel() == TrustLevel.TRUSTED
                && now.isBefore(actor.getExpiresAt());
    }
}
