package com.vpbank.dcp.auth.adapter.out.persistence.repository;

import com.vpbank.dcp.auth.adapter.out.persistence.entity.TrustedDeviceEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface TrustedDeviceJpaRepository extends JpaRepository<TrustedDeviceEntity, UUID> {

    /** The live row of one installation: LIVE_SLOT is 1 while PENDING/ACTIVE/SUSPENDED (generated column). */
    Optional<TrustedDeviceEntity> findByCustomerIdAndChannelAndClientDeviceIdLookupAndLiveSlot(
            String customerId, String channel, byte[] clientDeviceIdLookup, Byte liveSlot);

    List<TrustedDeviceEntity> findByCustomerIdAndChannelAndLiveSlotOrderByCreatedAtAsc(String customerId, String channel,
                                                                                       Byte liveSlot);
}
