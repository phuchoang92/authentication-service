package com.vpbank.dcp.core.port.in.session;

import com.vpbank.dcp.core.domain.customer.SubjectId;
import java.util.Objects;
import java.util.UUID;

/** Identifies a confirmed operation; the current storage snapshot still authorize activation. */
public record ActivateSessionCommand(UUID operationId, SubjectId subject) {
    public ActivateSessionCommand {
        Objects.requireNonNull(operationId, "operationId");
        Objects.requireNonNull(subject, "subject");
    }
}
