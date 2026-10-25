package com.vpbank.dcp.auth.application.port.in;

import com.vpbank.dcp.auth.application.command.RegisterCustomerCommand;
import com.vpbank.dcp.auth.application.result.RegisterCustomerResult;

/** Customer → Auth: create the login account of a customer who finished onboarding (contract §1). */
public interface RegisterCustomerUseCase {
    RegisterCustomerResult register(RegisterCustomerCommand command);
}
