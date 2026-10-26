package com.vpbank.dcp.auth.application.result;

import java.util.List;

/** The primary device's view of the waiting requests (slice 6). */
public sealed interface ListPendingDevicesResult {
    record Pending(List<PendingDeviceSummary> devices) implements ListPendingDevicesResult {
        public Pending {
            devices = List.copyOf(devices);
        }
    }

    /** The caller's session is not an ACTIVE session on the customer's current primary device. */
    record NotPrimaryDevice() implements ListPendingDevicesResult { }

    record SessionGone() implements ListPendingDevicesResult { }

    record Unavailable() implements ListPendingDevicesResult { }
}
