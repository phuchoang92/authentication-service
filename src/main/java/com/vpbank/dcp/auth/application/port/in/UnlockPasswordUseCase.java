package com.vpbank.dcp.auth.application.port.in;

import com.vpbank.dcp.auth.application.result.UnlockPasswordResult;
import com.vpbank.dcp.auth.domain.model.CustomerId;

/** Bank staff → Auth (internal): clear a customer's password lockout, including a permanent one. */
public interface UnlockPasswordUseCase {
    UnlockPasswordResult unlock(CustomerId customerId);
}
