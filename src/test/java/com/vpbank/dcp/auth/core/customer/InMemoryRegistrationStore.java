package com.vpbank.dcp.auth.core.customer;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Test double with the same rules as the MySQL store: one open request per customer and per
 * username (case-insensitive), steps only from the expected version and state.
 */
final class InMemoryRegistrationStore implements RegistrationStore {
    final List<Registration> rows = new ArrayList<>();
    final Set<String> identityUserNames = new HashSet<>();
    boolean unavailable;

    @Override
    public ReserveResult reserve(UUID requestId, String customerId, String userName,
                                 RequestDigest requestDigest, Instant expiresAt, Instant now) {
        check();
        Optional<Registration> open = rows.stream()
                .filter(row -> !row.state().finished() && row.customerId().equals(customerId)).findFirst();
        if (open.isPresent()) {
            return new ReserveResult.CustomerHasOpen(open.get());
        }
        if (rows.stream().anyMatch(row -> !row.state().finished()
                && row.userName().equalsIgnoreCase(userName))) {
            return new ReserveResult.UserNameTaken();
        }
        Registration created = new Registration(requestId, customerId, userName, requestDigest,
                RegistrationState.RESERVED, null, null, expiresAt, 0);
        rows.add(created);
        return new ReserveResult.Reserved(created);
    }

    @Override
    public Optional<Registration> findLatest(String customerId) {
        check();
        return rows.reversed().stream().filter(row -> row.customerId().equals(customerId)).findFirst();
    }

    @Override
    public boolean markUserCreated(UUID requestId, long version, String identityIssuer,
                                   String identitySubject, Instant now) {
        return move(requestId, version, Set.of(RegistrationState.RESERVED), RegistrationState.USER_CREATED,
                identityIssuer, identitySubject);
    }

    @Override
    public boolean markSmsAccepted(UUID requestId, long version, Instant now) {
        return move(requestId, version, Set.of(RegistrationState.USER_CREATED), RegistrationState.SMS_ACCEPTED,
                null, null);
    }

    @Override
    public CompleteResult complete(UUID requestId, long version, Instant now) {
        check();
        Registration row = find(requestId);
        if (row.version() != version || row.state() != RegistrationState.SMS_ACCEPTED) {
            return CompleteResult.STALE;
        }
        if (!identityUserNames.add(row.userName().toLowerCase(Locale.ROOT))) {
            return CompleteResult.IDENTITY_TAKEN;
        }
        move(requestId, version, Set.of(RegistrationState.SMS_ACCEPTED), RegistrationState.READY, null, null);
        return CompleteResult.COMPLETED;
    }

    @Override
    public boolean markFailed(UUID requestId, long version, Instant now) {
        return move(requestId, version, Set.of(RegistrationState.RESERVED, RegistrationState.USER_CREATED,
                RegistrationState.SMS_ACCEPTED), RegistrationState.FAILED, null, null);
    }

    Registration only() {
        return rows.getLast();
    }

    private boolean move(UUID requestId, long version, Set<RegistrationState> from, RegistrationState to,
                         String issuer, String subject) {
        check();
        Registration row = find(requestId);
        if (row.version() != version || !from.contains(row.state())) {
            return false;
        }
        rows.set(rows.indexOf(row), new Registration(row.requestId(), row.customerId(), row.userName(),
                row.requestDigest(), to, issuer != null ? issuer : row.identityIssuer(),
                subject != null ? subject : row.identitySubject(), row.expiresAt(), version + 1));
        return true;
    }

    private Registration find(UUID requestId) {
        return rows.stream().filter(row -> row.requestId().equals(requestId)).findFirst().orElseThrow();
    }

    private void check() {
        if (unavailable) {
            throw new RegistrationStoreUnavailableException(new RuntimeException("down"));
        }
    }
}
