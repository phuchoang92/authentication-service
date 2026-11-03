package com.vpbank.dcp.auth.application.command;

import com.vpbank.dcp.auth.domain.model.AdmittedSession;
import java.util.Objects;

/** Slice 6: the primary device lists the installations waiting for its approval (ACTIVE session). */
public record ListPendingDevicesCommand(AdmittedSession admitted) {
    public ListPendingDevicesCommand {
        Objects.requireNonNull(admitted, "admitted");
    }

    @Override
    public String toString() {
        return "ListPendingDevicesCommand[redacted]";
    }
}
