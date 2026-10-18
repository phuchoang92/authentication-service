package com.vpbank.dcp.infrastructure.persistence.repository;

import com.vpbank.dcp.core.port.out.device.RecordDeviceRevocation;
import com.vpbank.dcp.infrastructure.persistence.entity.SecurityAuditEventEntity;
import com.vpbank.dcp.infrastructure.persistence.entity.SecurityAuditEventHeader;
import com.vpbank.dcp.infrastructure.persistence.projection.DeviceRevocationAuditView;
import java.security.MessageDigest;
import java.time.Clock;
import java.util.Objects;
import java.util.UUID;
import org.springframework.stereotype.Repository;

@Repository
public class SecurityAuditPersistenceRepository {
    private final SecurityAuditJpaRepository events;
    private final Clock clock;

    public SecurityAuditPersistenceRepository(SecurityAuditJpaRepository events, Clock clock) {
        this.events = Objects.requireNonNull(events, "events");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    public DeviceRevocationAuditView findDeviceRevocation(RecordDeviceRevocation command,
                                                           byte[] commandDigest) {
        return events.findRevocation(command.bindingId().value(), command.owner().subject().value(),
                        command.owner().channel())
                .filter(event -> event.commandDigest() != null)
                .filter(event -> MessageDigest.isEqual(event.commandDigest(), commandDigest))
                .map(event -> new DeviceRevocationAuditView(event.operationId(),
                        event.deviceSecurityVersion(), hasPrimaryClear(command)))
                .orElse(null);
    }

    public void insertDeviceRevoked(RecordDeviceRevocation command, long securityVersion,
                                    byte[] commandDigest) {
        SecurityAuditEventEntity event = SecurityAuditEventEntity.deviceRevoked(
                header(command, 1), command.bindingId().value(), securityVersion,
                command.reason().code(), commandDigest);
        events.saveAndFlush(event);
    }

    public void insertPrimaryCleared(RecordDeviceRevocation command) {
        SecurityAuditEventEntity event = SecurityAuditEventEntity.primaryCleared(
                header(command, 2), command.bindingId().value());
        events.saveAndFlush(event);
    }

    private boolean hasPrimaryClear(RecordDeviceRevocation command) {
        return events.hasPrimaryClear(command.operationId(), command.owner().subject().value(),
                command.owner().channel(), command.bindingId().value());
    }

    private SecurityAuditEventHeader header(RecordDeviceRevocation command, int sequence) {
        return new SecurityAuditEventHeader(UUID.randomUUID(), command.owner().subject().value(),
                command.owner().channel(), command.operationId(), sequence,
                command.actor().type().code(), command.actor().id(), command.occurredAt(),
                clock.instant());
    }
}
