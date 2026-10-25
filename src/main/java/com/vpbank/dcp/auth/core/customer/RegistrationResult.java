package com.vpbank.dcp.auth.core.customer;

import java.util.Objects;
import java.util.UUID;

public sealed interface RegistrationResult {

    /** The login account exists. {@code created} is false when a retry found it already READY. */
    record Ready(UUID requestId, String customerId, String userName, boolean created)
            implements RegistrationResult {
        public Ready {
            Objects.requireNonNull(requestId, "requestId");
            Objects.requireNonNull(customerId, "customerId");
            Objects.requireNonNull(userName, "userName");
        }
    }

    /** Same customer with other data, or the username / identity belongs to someone else. */
    record IdentityConflict() implements RegistrationResult { }

    /** The customer is not eligible, or the phone or email is not the verified one. */
    record ProfileIncomplete() implements RegistrationResult { }

    /**
     * A partner or the database did not answer, or an earlier attempt has an unknown outcome.
     * Nothing is retried blindly; the request id stays for manual reconciliation.
     */
    record Unavailable() implements RegistrationResult { }
}
