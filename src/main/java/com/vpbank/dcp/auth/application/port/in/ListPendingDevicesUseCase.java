package com.vpbank.dcp.auth.application.port.in;

import com.vpbank.dcp.auth.application.command.ListPendingDevicesCommand;
import com.vpbank.dcp.auth.application.result.ListPendingDevicesResult;

/** Slice 6, approval of a new device by the current primary device (DD 20 §4, phase 4). */
public interface ListPendingDevicesUseCase {
    ListPendingDevicesResult pending(ListPendingDevicesCommand command);
}
