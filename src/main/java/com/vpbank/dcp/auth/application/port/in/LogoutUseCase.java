package com.vpbank.dcp.auth.application.port.in;

/** App → Auth (session-checked): end the current session. Idempotent from the app's view. */
public interface LogoutUseCase {
    LogoutResult logout(LogoutCommand command);
}
