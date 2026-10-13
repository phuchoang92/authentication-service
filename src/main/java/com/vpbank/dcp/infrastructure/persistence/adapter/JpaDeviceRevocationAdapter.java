package com.vpbank.dcp.infrastructure.persistence.adapter;

import com.vpbank.dcp.core.port.out.device.DeviceRevocationRecordResult;
import com.vpbank.dcp.core.port.out.device.DeviceRevocationRepository;
import com.vpbank.dcp.core.port.out.device.RecordDeviceRevocation;
import com.vpbank.dcp.infrastructure.persistence.codec.DeviceRevocationCommandDigest;
import com.vpbank.dcp.infrastructure.persistence.projection.DeviceRevocationAuditView;
import com.vpbank.dcp.infrastructure.persistence.projection.TrustedDeviceStateView;
import com.vpbank.dcp.infrastructure.persistence.repository.SecurityAuditPersistenceRepository;
import com.vpbank.dcp.infrastructure.persistence.repository.TrustedDeviceRevocationPersistenceRepository;
import java.util.Objects;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.support.TransactionTemplate;

/** Records only the SQL transition; a caller must confirm live denial before reporting revoke success. */
@Repository
public class JpaDeviceRevocationAdapter implements DeviceRevocationRepository {
    private final TrustedDeviceRevocationPersistenceRepository devices;
    private final SecurityAuditPersistenceRepository audit;
    private final DeviceRevocationCommandDigest commandDigests;
    private final TransactionTemplate transactions;

    public JpaDeviceRevocationAdapter(TrustedDeviceRevocationPersistenceRepository devices,
                                      SecurityAuditPersistenceRepository audit,
                                      DeviceRevocationCommandDigest commandDigests,
                                      TransactionTemplate transactions) {
        this.devices = Objects.requireNonNull(devices, "devices");
        this.audit = Objects.requireNonNull(audit, "audit");
        this.commandDigests = Objects.requireNonNull(commandDigests, "commandDigests");
        this.transactions = Objects.requireNonNull(transactions, "transactions");
    }

    @Override
    public DeviceRevocationRecordResult recordRevocation(RecordDeviceRevocation command) {
        Objects.requireNonNull(command, "command");
        byte[] commandDigest = commandDigests.calculate(command);
        return Objects.requireNonNull(transactions.execute(
                ignored -> recordLocked(command, commandDigest)));
    }

    private DeviceRevocationRecordResult recordLocked(RecordDeviceRevocation command,
                                                      byte[] commandDigest) {
        if (!devices.lockCustomer(command)) {
            return new DeviceRevocationRecordResult.Conflict();
        }
        boolean primaryTarget = command.bindingId().equals(devices.findPrimary(command));
        TrustedDeviceStateView device = devices.lockDevice(command);
        if (device == null) {
            return new DeviceRevocationRecordResult.Conflict();
        }
        if ("REVOKED".equals(device.status())) {
            return alreadyRecorded(command, commandDigest, device);
        }
        if (!("ACTIVE".equals(device.status()) || "PENDING_RESET".equals(device.status()))
                || device.version() != command.expectedVersion()
                || device.deviceSecurityVersion() >= 9007199254740991L) {
            return new DeviceRevocationRecordResult.Conflict();
        }
        if (devices.markRevoked(command) != 1) {
            return new DeviceRevocationRecordResult.Conflict();
        }
        long securityVersion = device.deviceSecurityVersion() + 1;
        audit.insertDeviceRevoked(command, securityVersion, commandDigest);
        if (primaryTarget) {
            audit.insertPrimaryCleared(command);
        }
        return new DeviceRevocationRecordResult.Recorded(securityVersion, primaryTarget);
    }

    private DeviceRevocationRecordResult alreadyRecorded(RecordDeviceRevocation command,
                                                         byte[] commandDigest,
                                                         TrustedDeviceStateView device) {
        DeviceRevocationAuditView previous = audit.findDeviceRevocation(command, commandDigest);
        if (previous == null || !previous.operationId().equals(command.operationId())
                || previous.deviceSecurityVersion() != device.deviceSecurityVersion()) {
            return new DeviceRevocationRecordResult.Conflict();
        }
        return new DeviceRevocationRecordResult.AlreadyRecorded(
                previous.deviceSecurityVersion(), previous.primaryCleared());
    }
}
