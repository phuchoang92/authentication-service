package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common;

import com.vpbank.dcp.auth.domain.model.ServiceId;
import java.util.Objects;

/**
 * What {@link ServiceClientAssertionFilter} leaves on the request: the internal service whose client assertion
 * was verified and used once. The controller hands it to the REST mapper unopened; the mapper puts the
 * {@link ServiceId} into the command, so the body can never name the caller.
 */
public record VerifiedServiceCaller(ServiceId caller) {
    public VerifiedServiceCaller {
        Objects.requireNonNull(caller, "caller");
    }
}
