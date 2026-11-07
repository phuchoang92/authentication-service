package com.vpbank.dcp.auth.application.command;

import com.vpbank.dcp.auth.domain.enums.ServiceScope;
import com.vpbank.dcp.auth.domain.model.BusinessReference;
import com.vpbank.dcp.auth.domain.model.ServiceId;
import lombok.NonNull;

/**
 * An internal service asks for a scoped token (slice 12). {@code callingService} is the service the client-assertion
 * filter verified, never a value from the body. {@code businessReference} is the journey the token is for and
 * may be null; whether the scope needs one is the service's decision.
 */
public record IssueServiceTokenCommand(@NonNull ServiceId callingService,
                                       @NonNull ServiceScope scope,
                                       BusinessReference businessReference) {
}
