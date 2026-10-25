package com.vpbank.dcp.auth.application.port.in;

import com.vpbank.dcp.auth.application.command.LoginCommand;
import com.vpbank.dcp.auth.application.result.LoginResult;

/** App → Auth (via BFF, no session): username/password login that issues a session (slice 2). */
public interface LoginUseCase {
    LoginResult login(LoginCommand command);
}
