package com.vpbank.dcp.core.port.out.authority;

public interface AuthorityLeaseRepository {

    LeaseChangeResult closeWithNewFence(AuthorityLeaseChange change);
}
