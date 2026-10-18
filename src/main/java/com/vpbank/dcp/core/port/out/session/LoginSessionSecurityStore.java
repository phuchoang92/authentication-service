package com.vpbank.dcp.core.port.out.session;

import com.vpbank.dcp.core.domain.device.BindingId;
import com.vpbank.dcp.core.domain.customer.SubjectId;
import java.util.Optional;
import java.util.UUID;

/** Reads Customer then device under one short database transaction. */
public interface LoginSessionSecurityStore {
    Optional<LoginSessionSecurity> current(SubjectId owner, BindingId bindingId, String channel);
}
