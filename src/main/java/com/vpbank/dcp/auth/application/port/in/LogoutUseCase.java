package com.vpbank.dcp.auth.application.port.in;

import com.vpbank.dcp.auth.application.command.LogoutCommand;
import com.vpbank.dcp.auth.application.result.LogoutResult;

/** App → Auth (session-checked): end the current session. Idempotent from the app's view. */
public interface LogoutUseCase {
    LogoutResult logout(LogoutCommand command);
}
