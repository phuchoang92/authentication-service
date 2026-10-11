package com.vpbank.dcp.core.port.out.replay;

import java.util.Objects;

public final class ReplayAuthorityUnavailableException extends RuntimeException {

    public ReplayAuthorityUnavailableException(Throwable cause) {
        super("Replay authority is unavailable", Objects.requireNonNull(cause, "cause"));
    }
}
