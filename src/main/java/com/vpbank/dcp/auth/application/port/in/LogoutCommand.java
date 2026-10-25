package com.vpbank.dcp.auth.application.port.in;

import com.vpbank.dcp.auth.domain.model.OpaqueToken;

import java.util.Objects;

/** The session to end, named by the token the app presented. */
public record LogoutCommand(OpaqueToken token) {
    public LogoutCommand {
        Objects.requireNonNull(token, "token");
    }
}
