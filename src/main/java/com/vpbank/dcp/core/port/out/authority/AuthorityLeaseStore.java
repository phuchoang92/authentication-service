package com.vpbank.dcp.core.port.out.authority;

public interface AuthorityLeaseStore {

    LeaseChangeResult closeWithNewFence(AuthorityLeaseChange change);
}
