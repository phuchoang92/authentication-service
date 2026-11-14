package com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository;

import com.vpbank.dcp.auth.domain.enums.DeviceStatus;
import com.vpbank.dcp.auth.domain.enums.TrustLevel;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.entity.TrustedDeviceEntity;
import jakarta.persistence.LockModeType;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface TrustedDeviceJpaRepository extends JpaRepository<TrustedDeviceEntity, UUID> {

    Optional<TrustedDeviceEntity> findByCustomerIdAndChannelAndClientDeviceIdLookup(
            String customerId, String channel, byte[] clientDeviceIdLookup);

    @Query("""
            select device
            from TrustedDeviceEntity device
            join PrimaryTrustedDeviceEntity primaryDevice
              on primaryDevice.key.customerId = device.customerId
             and primaryDevice.key.channel = device.channel
             and primaryDevice.primaryDeviceId = device.id
            where device.customerId = :customerId
              and device.channel = :channel
              and device.clientDeviceIdLookup = :deviceIdLookup
            """)
    Optional<TrustedDeviceEntity> findLivePrimary(
            @Param("customerId") String customerId,
            @Param("channel") String channel,
            @Param("deviceIdLookup") byte[] deviceIdLookup);

    /** The bulk update bypasses entity callbacks and optimistic locking; set updatedAt and version explicitly. */
    @Modifying
    @Query("""
            update TrustedDeviceEntity device
            set device.lastSuccessfulLoginAt = :loggedInAt,
                device.updatedAt = :updatedAt,
                device.version = device.version + 1
            where device.id = :deviceId
              and device.version = :expectedVersion
              and device.status = :activeStatus
              and device.trustLevel = :trustedLevel
              and device.expiresAt > :loggedInAt
              and (device.lastSuccessfulLoginAt is null or device.lastSuccessfulLoginAt < :loggedInAt)
            """)
    int updateLastLoginIfCurrent(
            @Param("deviceId") UUID deviceId,
            @Param("expectedVersion") long expectedVersion,
            @Param("loggedInAt") Instant loggedInAt,
            @Param("updatedAt") Instant updatedAt,
            @Param("activeStatus") DeviceStatus activeStatus,
            @Param("trustedLevel") TrustLevel trustedLevel);

    List<TrustedDeviceEntity> findByCustomerIdAndChannelOrderByCreatedAtAsc(String customerId, String channel);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    List<TrustedDeviceEntity> findByCustomerIdAndChannelOrderById(String customerId, String channel);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<TrustedDeviceEntity> findByIdAndCustomerIdAndChannel(UUID id, String customerId, String channel);

    @Modifying
    @Query("""
            delete from TrustedDeviceEntity device
            where device.id = :id and device.version = :version
            """)
    int deleteIfCurrent(@Param("id") UUID id, @Param("version") long version);
}
