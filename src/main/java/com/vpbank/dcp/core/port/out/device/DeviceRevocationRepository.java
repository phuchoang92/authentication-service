package com.vpbank.dcp.core.port.out.device;

public interface DeviceRevocationRepository {
    DeviceRevocationRecordResult recordRevocation(RecordDeviceRevocation command);
}
