package com.vpbank.dcp.auth.application.command;

import com.vpbank.dcp.auth.domain.model.AdmittedSession;
import lombok.NonNull;

/** Slice 6: the requesting device polls where its approval stands (restricted session). */
public record ApprovalStatusCommand(@NonNull AdmittedSession admitted) {
    @Override
    public String toString() {
        return "ApprovalStatusCommand[redacted]";
    }
}
