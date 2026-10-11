package com.vpbank.dcp.core.port.out.guard;

import java.util.Objects;

public final class SubjectGuardUnavailableException extends RuntimeException {

    public SubjectGuardUnavailableException(Throwable cause) {
        super("Subject guard authority is unavailable", Objects.requireNonNull(cause, "cause"));
    }
}
