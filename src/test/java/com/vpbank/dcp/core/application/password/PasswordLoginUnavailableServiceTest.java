package com.vpbank.dcp.core.application.password;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.vpbank.dcp.core.port.in.password.PasswordLoginCommand;
import com.vpbank.dcp.core.port.in.password.PasswordLoginResult;
import org.junit.jupiter.api.Test;

class PasswordLoginUnavailableServiceTest {

    @Test
    void retiredLoginStorageCannotProduceAnActiveSession() {
        PasswordLoginUnavailableService login = new PasswordLoginUnavailableService();

        assertThat(login.login(mock(PasswordLoginCommand.class)))
                .isInstanceOf(PasswordLoginResult.TemporarilyUnavailable.class);
    }
}
