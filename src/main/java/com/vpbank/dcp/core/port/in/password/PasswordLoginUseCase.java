package com.vpbank.dcp.core.port.in.password;

public interface PasswordLoginUseCase {
    PasswordLoginResult login(PasswordLoginCommand command);
}
