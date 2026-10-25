package com.vpbank.dcp.core.session;

public final class LoginSessionSecurityUnavailableException extends RuntimeException {
    public LoginSessionSecurityUnavailableException(Throwable cause) {
        super("Current session security state is unavailable", cause);
    }
}
