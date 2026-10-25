package com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.adapter;

import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.common.DeviceIdProtection;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.entity.PrimaryTrustedDeviceEntity;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.entity.TrustedDeviceEntity;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.mapper.TrustedDevicePersistenceMapper;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.PrimaryTrustedDeviceJpaRepository;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.TrustedDeviceAuditJpaRepository;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.TrustedDeviceJpaRepository;
import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.port.out.repository.TrustedDeviceRepository;
import com.vpbank.dcp.auth.domain.model.Channel;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.DeviceStatus;
import com.vpbank.dcp.auth.domain.model.TrustedDevice;
import com.vpbank.dcp.auth.domain.model.TrustedDeviceId;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.orm.ObjectOptimisticLockingFailureException;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.interceptor.TransactionAspectSupport;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * {@link TrustedDeviceRepository} over Spring Data JPA. The database only stops races (one live
 * row per installation, one primary per customer + channel); the aggregate decided every rule.
 * {@link #trustFirstDevice} is the one multi-table transaction: device row, primary row and the
 * audit events 0..1 together, or nothing. Spring exceptions never leave this class.
 */
@RequiredArgsConstructor
public class TrustedDevicePersistenceAdapter implements TrustedDeviceRepository {
    private static final Byte LIVE = 1;
    static final String EVENT_TRUSTED = "DEVICE_TRUSTED";
    static final String EVENT_PRIMARY = "PRIMARY_ASSIGNED";
    static final String EVENT_LOGIN = "DEVICE_LOGIN";
    static final String EVENT_EXPIRED = "DEVICE_EXPIRED";

    @NonNull private final TrustedDeviceJpaRepository devices;
    @NonNull private final PrimaryTrustedDeviceJpaRepository primaries;
    @NonNull private final TrustedDeviceAuditJpaRepository audit;
    @NonNull private final DeviceIdProtection protection;
    @NonNull private final Clock clock;

    @Override
    public Optional<TrustedDevice> findLive(CustomerId customerId, Channel channel, DeviceId deviceId) {
        return translate(() -> devices.findByCustomerIdAndChannelAndClientDeviceIdLookupAndLiveSlot(customerId.value(),
                        channel.name(), protection.lookup(customerId, channel, deviceId), LIVE)
                .flatMap(entity -> TrustedDevicePersistenceMapper.toDomain(entity, protection)));
    }

    @Override
    public List<TrustedDevice> findLive(CustomerId customerId, Channel channel) {
        return translate(() -> devices.findByCustomerIdAndChannelAndLiveSlotOrderByCreatedAtAsc(customerId.value(),
                        channel.name(), LIVE).stream()
                .flatMap(entity -> TrustedDevicePersistenceMapper.toDomain(entity, protection).stream())
                .toList());
    }

    @Override
    public Optional<TrustedDeviceId> findPrimary(CustomerId customerId, Channel channel) {
        return translate(() -> primaries.findById(new PrimaryTrustedDeviceEntity.Key(customerId.value(), channel.name()))
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
        try {
            if (primaries.existsById(new PrimaryTrustedDeviceEntity.Key(device.customerId().value(), device.channel().name()))) {
                return new TrustFirstResult.AlreadyHasDevice();
            }
            TrustedDeviceEntity saved = devices.saveAndFlush(TrustedDevicePersistenceMapper.toEntity(device, protection));
            primaries.saveAndFlush(TrustedDevicePersistenceMapper.toPrimary(device, now));
            audit.save(TrustedDevicePersistenceMapper.toAudit(device, correlationId, 0, EVENT_TRUSTED, "LOGIN",
                    "FIRST_DEVICE", now));
            audit.saveAndFlush(TrustedDevicePersistenceMapper.toAudit(device, correlationId, 1, EVENT_PRIMARY, "LOGIN",
                    "FIRST_DEVICE", now));
            return new TrustFirstResult.Trusted(TrustedDevicePersistenceMapper.toDomain(saved, protection).orElseThrow());
        } catch (DataIntegrityViolationException raced) {
            // UQ_TD_LIVE_INSTALLATION or the primary's primary key: another login got there first.
            TransactionAspectSupport.currentTransactionStatus().setRollbackOnly();
            return new TrustFirstResult.AlreadyHasDevice();
        } catch (DataAccessException failure) {
            throw new RepositoryUnavailableException(failure);
        }
    }

    @Override
    public Optional<TrustedDevice> saveIfCurrent(TrustedDevice changed, String correlationId) {
        try {
            Optional<TrustedDeviceEntity> current = devices.findById(changed.id().value());
            if (current.isEmpty() || current.get().getVersion() != changed.version()) {
                return Optional.empty();
            }
            boolean expiring = changed.status() == DeviceStatus.EXPIRED && current.get().getStatus().live();
            TrustedDevicePersistenceMapper.apply(current.get(), changed);
            TrustedDeviceEntity saved = devices.saveAndFlush(current.get());
            if (expiring) {
                audit.saveAndFlush(TrustedDevicePersistenceMapper.toAudit(changed, correlationId, 0, EVENT_EXPIRED, "POLICY",
                        "DEVICE_CAP", clock.instant()));
            }
            return TrustedDevicePersistenceMapper.toDomain(saved, protection);
        } catch (ObjectOptimisticLockingFailureException stale) {
            return Optional.empty();
        } catch (DataAccessException failure) {
            throw new RepositoryUnavailableException(failure);
        }
    }

    private static <T> T translate(Supplier<T> call) {
        try {
            return call.get();
        } catch (DataAccessException failure) {
            throw new RepositoryUnavailableException(failure);
        }
    }
}
