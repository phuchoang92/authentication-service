package com.vpbank.dcp.core.port.in.password;

import com.vpbank.dcp.core.application.password.PasswordAdmissionCommand;
import com.vpbank.dcp.core.application.password.PasswordAuthenticationResult;

public interface AuthenticateWithPassword {
    PasswordAuthenticationResult authenticate(PasswordAdmissionCommand command);
}
