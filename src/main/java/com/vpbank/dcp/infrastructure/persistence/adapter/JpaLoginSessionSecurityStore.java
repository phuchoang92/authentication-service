package com.vpbank.dcp.infrastructure.persistence.adapter;

import com.vpbank.dcp.core.domain.device.BindingId;
import com.vpbank.dcp.core.domain.customer.SubjectId;
import com.vpbank.dcp.core.port.out.session.LoginSessionSecurity;
import com.vpbank.dcp.core.port.out.session.LoginSessionSecurityStore;
import com.vpbank.dcp.core.port.out.session.LoginSessionSecurityUnavailableException;
import com.vpbank.dcp.core.port.out.session.SessionSecurityVersions;
import com.vpbank.dcp.core.port.out.session.StoredCustomerSecurity;
import com.vpbank.dcp.core.port.out.session.StoredDeviceSecurity;
import com.vpbank.dcp.infrastructure.persistence.repository.LoginSessionSecurityPersistenceRepository;
import com.vpbank.dcp.infrastructure.persistence.projection.LoginSessionSecurityView;
import java.time.ZoneOffset;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.dao.DataAccessException;
import org.springframework.transaction.TransactionException;

/** Short locked SQL read; HTTP, crypto and Redis stay outside this transaction. */
public final class JpaLoginSessionSecurityStore implements LoginSessionSecurityStore {
    private final LoginSessionSecurityPersistenceRepository repository;
    private final TransactionTemplate transactions;

    public JpaLoginSessionSecurityStore(LoginSessionSecurityPersistenceRepository repository,
                                        TransactionTemplate transactions) {
        this.repository = Objects.requireNonNull(repository);
        this.transactions = Objects.requireNonNull(transactions);
    }

    @Override
    public Optional<LoginSessionSecurity> current(SubjectId owner, BindingId bindingId, String channel) {
        Objects.requireNonNull(owner);
        Objects.requireNonNull(bindingId);
        Objects.requireNonNull(channel);
        try {
            Optional<LoginSessionSecurityView> current = Objects.requireNonNull(transactions.execute(
                    ignored -> repository.lockCurrent(owner.value(), bindingId.value(), channel)));
            return current.map(row -> new LoginSessionSecurity(
                    new StoredCustomerSecurity("ELIGIBLE".equals(row.customerStatus()),
                            row.customerStatusVersion()),
                    new StoredDeviceSecurity("ACTIVE".equals(row.deviceStatus()),
                            row.deviceExpiresAt().toInstant(ZoneOffset.UTC), row.devicePrimary()),
                    new SessionSecurityVersions(row.customerSecurityVersion(),
                            row.credentialSecurityVersion(), row.deviceSecurityVersion()),
                    row.biometricEnabled()));
        } catch (DataAccessException | TransactionException failure) {
            throw new LoginSessionSecurityUnavailableException(failure);
        }
    }
}
