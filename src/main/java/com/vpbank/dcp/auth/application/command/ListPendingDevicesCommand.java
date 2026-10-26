package com.vpbank.dcp.auth.application.command;

import com.vpbank.dcp.auth.domain.model.OpaqueToken;
import java.util.Objects;

/** Slice 6: the primary device lists the installations waiting for its approval (ACTIVE session). */
public record ListPendingDevicesCommand(OpaqueToken token) {
    public ListPendingDevicesCommand {
        Objects.requireNonNull(token, "token");
    }

    @Override
    public String toString() {
        return "ListPendingDevicesCommand[redacted]";
    }
}
