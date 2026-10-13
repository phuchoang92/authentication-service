package com.vpbank.dcp.core.port.out.device;

/** Does not represent completed online revocation. */
public sealed interface DeviceRevocationRecordResult {
    record Recorded(long deviceSecurityVersion, boolean primaryCleared)
            implements DeviceRevocationRecordResult { }

    record AlreadyRecorded(long deviceSecurityVersion, boolean primaryWasCleared)
            implements DeviceRevocationRecordResult { }

    record Conflict() implements DeviceRevocationRecordResult { }
}
