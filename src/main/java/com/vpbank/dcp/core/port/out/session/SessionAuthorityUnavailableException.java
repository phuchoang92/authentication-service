package com.vpbank.dcp.core.port.out.session;

public final class SessionAuthorityUnavailableException extends RuntimeException {
    public SessionAuthorityUnavailableException(Throwable cause) {
        super("Banking session authority is unavailable", cause);
    }
}
