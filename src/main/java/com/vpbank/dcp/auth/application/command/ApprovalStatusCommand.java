package com.vpbank.dcp.auth.application.command;

import com.vpbank.dcp.auth.domain.model.OpaqueToken;
import java.util.Objects;

/** Slice 6: the requesting device polls where its approval stands (restricted session). */
public record ApprovalStatusCommand(OpaqueToken token) {
    public ApprovalStatusCommand {
        Objects.requireNonNull(token, "token");
    }

    @Override
    public String toString() {
        return "ApprovalStatusCommand[redacted]";
    }
}
