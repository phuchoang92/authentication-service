package com.vpbank.dcp.infrastructure.persistence.mapper;

import com.vpbank.dcp.core.port.out.device.DeviceRevocationRecordResult;
import com.vpbank.dcp.infrastructure.persistence.projection.DeviceRevocationAuditView;

/** Converts stored revocation evidence into a result without changing security state. */
public final class DeviceRevocationPersistenceMapper {
    private DeviceRevocationPersistenceMapper() { }

    public static DeviceRevocationRecordResult.Recorded recorded(long securityVersion,
                                                                  boolean primaryCleared) {
        return new DeviceRevocationRecordResult.Recorded(securityVersion, primaryCleared);
    }

    public static DeviceRevocationRecordResult.AlreadyRecorded alreadyRecorded(
            DeviceRevocationAuditView audit) {
        return new DeviceRevocationRecordResult.AlreadyRecorded(
                audit.deviceSecurityVersion(), audit.primaryCleared());
    }
}
