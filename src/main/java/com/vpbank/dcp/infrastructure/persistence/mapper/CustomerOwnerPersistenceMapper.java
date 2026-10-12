package com.vpbank.dcp.infrastructure.persistence.mapper;

import com.vpbank.dcp.core.domain.customer.CustomerAuthenticationState;
import com.vpbank.dcp.core.domain.customer.CustomerStatus;
import com.vpbank.dcp.infrastructure.persistence.projection.CustomerOwnerView;

/** Restores Customer values without deciding eligibility or freshness. */
public final class CustomerOwnerPersistenceMapper {
    private CustomerOwnerPersistenceMapper() { }

    public static CustomerAuthenticationState toDomain(CustomerOwnerView view) {
        return new CustomerAuthenticationState(view.customerId(), CustomerStatus.valueOf(view.status()),
                view.statusVersion(), view.lastAccessBlockVersion(), view.checkedAt());
    }
}
