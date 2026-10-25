package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.port.out.repository.RegistrationRepository;
import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.domain.model.Registration;
import com.vpbank.dcp.auth.domain.model.RegistrationState;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

/**
 * Test double with the same rules as the MySQL adapter: one open request per customer and per
 * username (case-insensitive), a step is saved only from the expected version.
 */
final class InMemoryRegistrationRepository implements RegistrationRepository {
    final List<Registration> rows = new ArrayList<>();
    final Set<String> identityUserNames = new HashSet<>();
    boolean unavailable;

    @Override
    public ReserveResult reserve(Registration reserved) {
        check();
        Optional<Registration> open = rows.stream()
                .filter(row -> row.isOpen() && row.customerId().equals(reserved.customerId())).findFirst();
        if (open.isPresent()) {
            return new ReserveResult.CustomerHasOpen(open.get());
        }
        if (rows.stream().anyMatch(row -> row.isOpen() && row.userName().sameAs(reserved.userName()))) {
            return new ReserveResult.UserNameTaken();
        }
        rows.add(reserved);
        return new ReserveResult.Reserved(reserved);
    }

    @Override
    public Optional<Registration> findLatest(CustomerId customerId) {
        check();
        return rows.reversed().stream().filter(row -> row.customerId().equals(customerId)).findFirst();
    }

    @Override
    public Optional<Registration> save(Registration changed) {
        check();
        int index = indexOf(changed);
        if (index < 0 || rows.get(index).version() != changed.version()) {
            return Optional.empty();
        }
        Registration stored = changed.withVersion(changed.version() + 1);
        rows.set(index, stored);
        return Optional.of(stored);
    }

    @Override
    public CompleteResult complete(Registration completed) {
        check();
        int index = indexOf(completed);
        Registration row = rows.get(index);
        if (row.version() != completed.version() || row.state() != RegistrationState.SMS_ACCEPTED) {
            return CompleteResult.STALE;
        }
        if (!identityUserNames.add(row.userName().value().toLowerCase(Locale.ROOT))) {
            return CompleteResult.IDENTITY_TAKEN;
        }
        rows.set(index, completed.withVersion(completed.version() + 1));
        return CompleteResult.COMPLETED;
    }

    Registration only() {
        return rows.getLast();
    }

    private int indexOf(Registration registration) {
        for (int i = 0; i < rows.size(); i++) {
            if (rows.get(i).id().equals(registration.id())) {
                return i;
            }
        }
        return -1;
    }

    private void check() {
        if (unavailable) {
            throw new RepositoryUnavailableException(new RuntimeException("down"));
        }
    }
}
