package com.vpbank.dcp.infrastructure.adapter.out.persistence.authority;

import com.vpbank.dcp.core.port.out.authority.AuthorityLeaseChange;
import com.vpbank.dcp.core.port.out.authority.AuthorityLeaseRepository;
import com.vpbank.dcp.core.port.out.authority.LeaseChangeResult;
import java.util.Objects;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import com.vpbank.dcp.infrastructure.adapter.out.persistence.repository.authority.AuthorityLeasePersistenceRepository;

/** Delegates SQL binding and mapping to the persistence repository. */
@Repository
public class JpaAuthorityLeaseAdapter implements AuthorityLeaseRepository {
    private final AuthorityLeasePersistenceRepository repository;

    public JpaAuthorityLeaseAdapter(AuthorityLeasePersistenceRepository repository) {
        this.repository = Objects.requireNonNull(repository);
    }

    @Override
    @Transactional(propagation = Propagation.MANDATORY)
    public LeaseChangeResult closeWithNewFence(AuthorityLeaseChange change) {
        return repository.closeWithNewFence(change);
    }
}
