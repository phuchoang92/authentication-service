package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.port.out.CustomerAuthentication;
import com.vpbank.dcp.auth.application.port.out.CustomerAuthenticationRepository;
import com.vpbank.dcp.auth.application.port.out.RepositoryUnavailableException;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.PasswordLockout;
import com.vpbank.dcp.auth.domain.model.UserName;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/** Identity rows with the real adapter's contract: lockout writes are compare-and-set on version. */
final class InMemoryCustomerAuthenticationRepository implements CustomerAuthenticationRepository {
    final Map<CustomerId, CustomerAuthentication> rows = new HashMap<>();
    boolean unavailable;
    /** When > 0, the next lockout write is preceded by a concurrent failure landing first. */
    int concurrentFailures;

    @Override
    public Optional<CustomerAuthentication> findByUserName(UserName userName) {
        check();
        return rows.values().stream().filter(row -> row.userName().sameAs(userName)).findFirst();
    }

    @Override
    public Optional<CustomerAuthentication> saveLockoutIfCurrent(CustomerAuthentication current, PasswordLockout changed) {
        check();
        CustomerAuthentication stored = rows.get(current.customerId());
        if (concurrentFailures > 0 && stored != null) {
            concurrentFailures--;
            stored = stored.toBuilder().lockout(stored.lockout().afterFailure(java.time.Instant.EPOCH,
                    com.vpbank.dcp.auth.domain.model.LockoutPolicy.standard())).version(stored.version() + 1).build();
            rows.put(current.customerId(), stored);
        }
        if (stored == null || stored.version() != current.version()) {
            return Optional.empty();
        }
        CustomerAuthentication saved = stored.toBuilder().lockout(changed).version(stored.version() + 1).build();
        rows.put(current.customerId(), saved);
        return Optional.of(saved);
    }

    @Override
    public boolean unlock(CustomerId customerId) {
        check();
        CustomerAuthentication stored = rows.get(customerId);
        if (stored == null) {
            return false;
        }
        rows.put(customerId, stored.toBuilder().lockout(PasswordLockout.none()).version(stored.version() + 1).build());
        return true;
    }

    CustomerAuthentication only() {
        return rows.values().iterator().next();
    }

    private void check() {
        if (unavailable) {
            throw new RepositoryUnavailableException(new RuntimeException("down"));
        }
    }
}
