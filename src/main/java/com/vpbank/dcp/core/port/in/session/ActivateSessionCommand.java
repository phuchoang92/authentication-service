package com.vpbank.dcp.core.port.in.session;

import java.util.Objects;
import java.util.UUID;

/** Identifies a confirmed operation; current storage facts still authorize activation. */
public record ActivateSessionCommand(UUID operationId, UUID subjectId) {
    public ActivateSessionCommand {
        Objects.requireNonNull(operationId, "operationId");
        Objects.requireNonNull(subjectId, "subjectId");
    }
}
