package com.vpbank.dcp.core.device;

public interface DeviceRevocationRepository {
    DeviceRevocationRecordResult recordRevocation(RecordDeviceRevocation command);
}
