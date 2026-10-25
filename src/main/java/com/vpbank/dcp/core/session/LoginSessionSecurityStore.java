package com.vpbank.dcp.core.session;

import com.vpbank.dcp.core.device.BindingId;
import com.vpbank.dcp.core.customer.SubjectId;
import java.util.Optional;
import java.util.UUID;

/** Reads Customer then device under one short database transaction. */
public interface LoginSessionSecurityStore {
    Optional<LoginSessionSecurity> current(SubjectId owner, BindingId bindingId, String channel);
}
