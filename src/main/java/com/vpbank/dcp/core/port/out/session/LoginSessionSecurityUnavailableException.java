package com.vpbank.dcp.core.port.out.session;

public final class LoginSessionSecurityUnavailableException extends RuntimeException {
    public LoginSessionSecurityUnavailableException(Throwable cause) {
        super("Current session security state is unavailable", cause);
    }
}
