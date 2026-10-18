package com.vpbank.dcp.core.port.out.session;

import com.vpbank.dcp.core.domain.device.BindingId;
import com.vpbank.dcp.core.domain.customer.SubjectId;
import java.util.Objects;
import java.util.UUID;

/** Original operation and its confirmed owner, App and device binding. */
public record SessionActivationContext(UUID operationId,
                                       SubjectId subject,
                                       String appId,
                                       BindingId bindingId) {
    public SessionActivationContext {
        Objects.requireNonNull(operationId, "operationId");
        Objects.requireNonNull(subject, "subject");
        Objects.requireNonNull(appId, "appId");
        Objects.requireNonNull(bindingId, "bindingId");
    }
}
