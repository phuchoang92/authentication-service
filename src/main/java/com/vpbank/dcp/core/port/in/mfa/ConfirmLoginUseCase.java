package com.vpbank.dcp.core.port.in.mfa;

public interface ConfirmLoginUseCase {
    ConfirmLoginResult confirm(ConfirmLoginCommand command);
}
