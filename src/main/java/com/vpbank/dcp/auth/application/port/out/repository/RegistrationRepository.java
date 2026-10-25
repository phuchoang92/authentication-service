package com.vpbank.dcp.auth.application.port.out.repository;

import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.Registration;
import java.util.Optional;

/**
 * Registrations and the identity row written when one completes. Every method throws
 * {@link RepositoryUnavailableException} when the database cannot answer.
 */
public interface RegistrationRepository {

    /** Stores a RESERVED registration, unless the customer or the username already has an open one. */
    ReserveResult reserve(Registration reserved);

    Optional<Registration> findLatest(CustomerId customerId);

    /**
     * Saves one step. Succeeds only if the stored row still has {@code changed.version()}, and
     * then returns the registration with the version now stored. Empty means stale: another
     * caller moved the row first.
     */
    Optional<Registration> save(Registration changed);

    /**
     * Writes the identity row and the READY state together, in one transaction, from a
     * SMS_ACCEPTED row at {@code completed.version()}.
     */
    CompleteResult complete(Registration completed);

    sealed interface ReserveResult {
        record Reserved(Registration registration) implements ReserveResult { }

        record CustomerHasOpen(Registration existing) implements ReserveResult { }

        record UserNameTaken() implements ReserveResult { }
    }

    enum CompleteResult { COMPLETED, IDENTITY_TAKEN, STALE }
}
