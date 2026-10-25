package com.vpbank.dcp.auth.application.port.in;

/** App → Auth (via BFF, no session): username/password login that issues a session (slice 2). */
public interface LoginUseCase {
    LoginResult login(LoginCommand command);
}
