package com.vpbank.dcp.auth.application.command;

import com.vpbank.dcp.auth.domain.model.OpaqueToken;
import java.util.Objects;

/** The caller's devices on its channel; the session behind the token says who the caller is. */
public record ListDevicesCommand(OpaqueToken token) {
    public ListDevicesCommand {
        Objects.requireNonNull(token, "token");
    }

    @Override
    public String toString() {
        return "ListDevicesCommand[redacted]";
    }
}
