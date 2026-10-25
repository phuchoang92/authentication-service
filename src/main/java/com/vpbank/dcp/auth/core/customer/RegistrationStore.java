package com.vpbank.dcp.auth.core.customer;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * MySQL view of registrations. Each "mark" method moves one step forward only if the row is
 * still at the expected version, and returns false if another call moved it first. Every
 * method throws {@link RegistrationStoreUnavailableException} when the database cannot answer.
 */
public interface RegistrationStore {

    /** Starts a request in RESERVED, unless one is already open for the customer or username. */
    ReserveResult reserve(UUID requestId, String customerId, String userName,
                          RequestDigest requestDigest, Instant expiresAt, Instant now);

    /** The customer's most recent request, open or finished. */
    Optional<Registration> findLatest(String customerId);

    /** RESERVED → USER_CREATED, recording the Keycloak user it created. */
    boolean markUserCreated(UUID requestId, long version, String identityIssuer,
                            String identitySubject, Instant now);

    /** USER_CREATED → SMS_ACCEPTED. */
    boolean markSmsAccepted(UUID requestId, long version, Instant now);

    /**
     * SMS_ACCEPTED → READY and, in the same transaction, the customer's login identity.
     * Nothing changes if the username or Keycloak identity already belongs to someone.
     */
    CompleteResult complete(UUID requestId, long version, Instant now);

    /** Any open state → FAILED, which frees the slot for a new request. */
    boolean markFailed(UUID requestId, long version, Instant now);

    sealed interface ReserveResult {
        record Reserved(Registration registration) implements ReserveResult { }

        /** The customer already has an open request; it is returned so a retry can reuse it. */
        record CustomerHasOpen(Registration existing) implements ReserveResult { }

        record UserNameTaken() implements ReserveResult { }
    }

    enum CompleteResult { COMPLETED, IDENTITY_TAKEN, STALE }
}
