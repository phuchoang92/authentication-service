package com.vpbank.dcp.auth.application.command;

import com.vpbank.dcp.auth.domain.model.OpaqueToken;
import lombok.NonNull;

/** The caller's devices on its channel; the session behind the token says who the caller is. */
public record ListDevicesCommand(@NonNull OpaqueToken token) {
    @Override
    public String toString() {
        return "ListDevicesCommand[redacted]";
    }
}
