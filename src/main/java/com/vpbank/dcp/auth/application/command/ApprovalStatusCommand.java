package com.vpbank.dcp.auth.application.command;

import com.vpbank.dcp.auth.domain.model.AdmittedSession;
import java.util.Objects;

/** Slice 6: the requesting device polls where its approval stands (restricted session). */
public record ApprovalStatusCommand(AdmittedSession admitted) {
    public ApprovalStatusCommand {
        Objects.requireNonNull(admitted, "admitted");
    }

    @Override
    public String toString() {
        return "ApprovalStatusCommand[redacted]";
    }
}
