package com.vpbank.dcp.auth.application.command;

import com.vpbank.dcp.auth.domain.enums.ServiceScope;
import com.vpbank.dcp.auth.domain.model.BusinessReference;
import com.vpbank.dcp.auth.domain.model.ServiceId;
import java.util.Objects;

/**
 * An internal service asks for a scoped token (slice 12). {@code caller} is the service the client-assertion
 * filter verified, never a value from the body. {@code businessReference} is the journey the token is for and
 * may be null; whether the scope needs one is the service's decision.
 */
public record IssueServiceTokenCommand(ServiceId caller, ServiceScope scope, BusinessReference businessReference) {
    public IssueServiceTokenCommand {
        Objects.requireNonNull(caller, "caller");
        Objects.requireNonNull(scope, "scope");
    }
}
