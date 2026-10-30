package com.vpbank.dcp.auth.application.port.in;

import com.vpbank.dcp.auth.application.command.ListDevicesCommand;
import com.vpbank.dcp.auth.application.result.ListDevicesResult;

/** The caller's devices on its channel (slice 4), resolved from the session behind the token. */
public interface ListDevicesUseCase {
    ListDevicesResult list(ListDevicesCommand command);
}
