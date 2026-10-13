package com.vpbank.dcp.core.port.out.session;

import java.util.Optional;
import java.util.UUID;

/** Reads Customer then device under one short database transaction. */
public interface LoginSessionSecurityStore {
    Optional<LoginSessionSecurity> current(UUID customerId, UUID bindingId, String channel);
}
