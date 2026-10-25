package com.vpbank.dcp.auth.application.port.in;

/** Customer → Auth: create the login account of a customer who finished onboarding (contract §1). */
public interface RegisterCustomerUseCase {
    RegisterCustomerResult register(RegisterCustomerCommand command);
}
