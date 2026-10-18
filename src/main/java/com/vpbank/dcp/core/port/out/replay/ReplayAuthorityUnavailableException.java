package com.vpbank.dcp.core.port.out.replay;

import java.util.Objects;

public final class ReplayAuthorityUnavailableException extends RuntimeException {

    /** The authority answered, but cannot accept a first use now. */
    public ReplayAuthorityUnavailableException() {
        super("Replay authority is unavailable");
    }

    public ReplayAuthorityUnavailableException(Throwable cause) {
        super("Replay authority is unavailable", Objects.requireNonNull(cause, "cause"));
    }
}
