package com.vpbank.dcp.core.port.out.session;

import java.util.Objects;
import java.util.UUID;

/** Original operation and its confirmed owner, App and device binding. */
public record SessionActivationContext(UUID operationId,
                                       UUID journeyId,
                                       UUID subjectId,
                                       String appId,
                                       UUID bindingId) {
    public SessionActivationContext {
        Objects.requireNonNull(operationId, "operationId");
        Objects.requireNonNull(journeyId, "journeyId");
        Objects.requireNonNull(subjectId, "subjectId");
        Objects.requireNonNull(appId, "appId");
        Objects.requireNonNull(bindingId, "bindingId");
    }
}
