package com.vpbank.dcp.auth.application.port.in;

import com.vpbank.dcp.auth.domain.model.RegistrationId;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.UserName;

import java.util.Objects;

/** Business outcomes of {@link RegisterCustomerUseCase}; infrastructure failures are exceptions. */
public sealed interface RegisterCustomerResult {

    /** The login account exists. {@code created} is false when a retry found it already READY. */
    record Ready(RegistrationId requestId, CustomerId customerId, UserName userName, boolean created)
            implements RegisterCustomerResult {
        public Ready {
            Objects.requireNonNull(requestId, "requestId");
            Objects.requireNonNull(customerId, "customerId");
            Objects.requireNonNull(userName, "userName");
        }
    }

    /** Same customer with other data, or the username / identity belongs to someone else. */
    record IdentityConflict() implements RegisterCustomerResult { }

    /** The customer is not eligible, or the phone or email is not the verified one. */
    record ProfileIncomplete() implements RegisterCustomerResult { }

    /**
     * A partner or the database did not answer, or an earlier attempt has an unknown outcome.
     * Nothing is retried blindly; the request id stays for manual reconciliation.
     */
    record Unavailable() implements RegisterCustomerResult { }
}
