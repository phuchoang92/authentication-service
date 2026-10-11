package com.vpbank.dcp.core.port.out.authority;

import java.util.Objects;

public final class AuthorityControlUnavailableException extends RuntimeException {

    public AuthorityControlUnavailableException(Throwable cause) {
        super("Authority control is unavailable", Objects.requireNonNull(cause, "cause"));
    }
}
