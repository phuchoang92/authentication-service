package com.vpbank.archfixtures.infrastructure.persistence.repository;

import com.vpbank.archfixtures.infrastructure.persistence.adapter.BadSqlAdapter;
import com.vpbank.dcp.core.customer.VerifiedProviderIdentity;

public class BadRepository {
    BadSqlAdapter coordinator;

    public VerifiedProviderIdentity identity() {
        return new VerifiedProviderIdentity("issuer", "subject");
    }
}
