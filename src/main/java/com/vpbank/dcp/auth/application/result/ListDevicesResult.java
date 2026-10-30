package com.vpbank.dcp.auth.application.result;

import java.util.List;

/** Outcome of the device list: the devices, or why the caller may not see them. */
public sealed interface ListDevicesResult {
    record Devices(List<DeviceSummary> devices) implements ListDevicesResult {
        public Devices {
            devices = List.copyOf(devices);
        }
    }

    /** A restricted NEED_TRUSTED_DEVICE session reaches no device-management route (DD 20 §3). */
    record DeviceTrustRequired() implements ListDevicesResult { }

    record SessionGone() implements ListDevicesResult { }

    record Unavailable() implements ListDevicesResult { }
}
