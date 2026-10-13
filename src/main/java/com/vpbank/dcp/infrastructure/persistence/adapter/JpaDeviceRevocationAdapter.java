package com.vpbank.dcp.infrastructure.persistence.adapter;

import com.vpbank.dcp.core.port.out.device.DeviceRevocationRecordResult;
import com.vpbank.dcp.core.port.out.device.DeviceRevocationRepository;
import com.vpbank.dcp.core.port.out.device.RecordDeviceRevocation;
import com.vpbank.dcp.infrastructure.persistence.mapper.DeviceRevocationPersistenceMapper;
import com.vpbank.dcp.infrastructure.persistence.projection.DeviceRevocationAuditView;
import com.vpbank.dcp.infrastructure.persistence.projection.TrustedDeviceAppView;
import com.vpbank.dcp.infrastructure.persistence.projection.TrustedDeviceStateView;
import com.vpbank.dcp.infrastructure.persistence.repository.SecurityAuditPersistenceRepository;
import com.vpbank.dcp.infrastructure.persistence.repository.TrustedDeviceRevocationPersistenceRepository;
import com.vpbank.dcp.infrastructure.persistence.repository.UnexpectedDeviceRevocationStateException;
import java.util.Objects;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.support.TransactionTemplate;

/** Records only the SQL transition; a caller must confirm live denial before reporting revoke success. */
@Repository
public class JpaDeviceRevocationAdapter implements DeviceRevocationRepository {
    private final TrustedDeviceRevocationPersistenceRepository devices;
    private final SecurityAuditPersistenceRepository audit;
    private final TransactionTemplate transactions;

    public JpaDeviceRevocationAdapter(TrustedDeviceRevocationPersistenceRepository devices,
                                      SecurityAuditPersistenceRepository audit,
                                      TransactionTemplate transactions) {
        this.devices = Objects.requireNonNull(devices, "devices");
        this.audit = Objects.requireNonNull(audit, "audit");
        this.transactions = Objects.requireNonNull(transactions, "transactions");
    }

    @Override
    public DeviceRevocationRecordResult recordRevocation(RecordDeviceRevocation command) {
        Objects.requireNonNull(command, "command");
        return Objects.requireNonNull(transactions.execute(ignored -> recordLocked(command)));
    }

    private DeviceRevocationRecordResult recordLocked(RecordDeviceRevocation command) {
        TrustedDeviceAppView customerApp = devices.lockCustomerApp(command);
        if (customerApp == null) {
            return new DeviceRevocationRecordResult.Conflict();
        }
        TrustedDeviceStateView device = devices.lockDevice(command);
        if (device == null) {
            return new DeviceRevocationRecordResult.Conflict();
        }
        if ("REVOKED".equals(device.status())) {
            return alreadyRecorded(command, device);
        }
        if (!("ACTIVE".equals(device.status()) || "PENDING_RESET".equals(device.status()))
                || device.version() != command.expectedVersion()
                || device.deviceSecurityVersion() >= 9007199254740991L) {
            return new DeviceRevocationRecordResult.Conflict();
        }
        if (devices.markRevoked(command) != 1) {
            return new DeviceRevocationRecordResult.Conflict();
        }
        boolean primaryCleared = command.bindingId().equals(customerApp.primaryBindingId());
        if (primaryCleared && devices.clearPrimary(command, customerApp.version()) != 1) {
            throw new UnexpectedDeviceRevocationStateException();
        }
        long securityVersion = device.deviceSecurityVersion() + 1;
        audit.insertDeviceRevoked(command, securityVersion);
        if (primaryCleared) {
            audit.insertPrimaryCleared(command);
        }
        return DeviceRevocationPersistenceMapper.recorded(securityVersion, primaryCleared);
    }

    private DeviceRevocationRecordResult alreadyRecorded(RecordDeviceRevocation command,
                                                         TrustedDeviceStateView device) {
        DeviceRevocationAuditView previous = audit.findDeviceRevocation(command);
        if (previous == null || !previous.operationId().equals(command.operationId())
                || previous.deviceSecurityVersion() != device.deviceSecurityVersion()) {
            return new DeviceRevocationRecordResult.Conflict();
        }
        return DeviceRevocationPersistenceMapper.alreadyRecorded(previous);
    }
}
