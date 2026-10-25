package com.vpbank.dcp.auth.application.port.in;

import com.vpbank.dcp.auth.domain.model.Channel;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.Password;
import com.vpbank.dcp.auth.domain.model.UserName;
import lombok.Builder;

import java.util.Objects;

/**
 * One login attempt. {@code deviceId} may be null (slice 2 records it, slice 3 judges it).
 * {@code tokenEncryptionKey} is the app's public P-256 JWK as JSON text; the sealer validates it.
 */
@Builder
public record LoginCommand(UserName userName, Password password, Channel channel, DeviceId deviceId,
                           String tokenEncryptionKey) {
    public LoginCommand {
        Objects.requireNonNull(userName, "userName");
        Objects.requireNonNull(password, "password");
        Objects.requireNonNull(channel, "channel");
        Objects.requireNonNull(tokenEncryptionKey, "tokenEncryptionKey");
    }

    @Override
    public String toString() {
        return "LoginCommand[userName=" + userName + ", channel=" + channel + ", redacted]";
    }
}
