package com.vpbank.dcp.infrastructure.persistence.repository;

import com.vpbank.dcp.infrastructure.persistence.entity.SecurityAuditEventEntity;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.Repository;
import org.springframework.data.repository.query.Param;

public interface SecurityAuditJpaRepository extends Repository<SecurityAuditEventEntity, UUID> {
    @Query("select event from SecurityAuditEventEntity event "
            + "where event.eventType = 'DEVICE_REVOKED' "
            + "and event.trustedDeviceId = :bindingId "
            + "and event.authCustomerId = :customerId and event.channel = :channel")
    Optional<SecurityAuditEventEntity> findRevocation(@Param("bindingId") UUID bindingId,
                                                       @Param("customerId") UUID customerId,
                                                       @Param("channel") String channel);

    @Query("select count(event) > 0 from SecurityAuditEventEntity event "
            + "where event.eventType = 'PRIMARY_DEVICE_CHANGED' "
            + "and event.operationId = :operationId "
            + "and event.authCustomerId = :customerId and event.channel = :channel "
            + "and event.previousPrimaryDeviceId = :bindingId "
            + "and event.newPrimaryDeviceId is null")
    boolean hasPrimaryClear(@Param("operationId") UUID operationId,
                            @Param("customerId") UUID customerId,
                            @Param("channel") String channel,
                            @Param("bindingId") UUID bindingId);

    <S extends SecurityAuditEventEntity> S saveAndFlush(S event);
}
