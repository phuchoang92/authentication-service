package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.port.in.password.PasswordLoginCommand;
import com.vpbank.dcp.core.port.in.password.PasswordLoginResult;
import com.vpbank.dcp.core.port.in.password.PasswordLoginUseCase;
import java.util.Objects;

/** Explicitly denies login while the retired journey/operation storage is replaced. */
public final class PasswordLoginUnavailableService implements PasswordLoginUseCase {

    @Override
    public PasswordLoginResult login(PasswordLoginCommand command) {
        Objects.requireNonNull(command, "command");
        return new PasswordLoginResult.TemporarilyUnavailable();
    }
}
