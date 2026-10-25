package com.vpbank.dcp.auth.application.port.in;

import com.vpbank.dcp.auth.domain.model.Channel;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.DevicePlatform;
import com.vpbank.dcp.auth.domain.model.Password;
import com.vpbank.dcp.auth.domain.model.UserName;
import lombok.Builder;

import java.util.Objects;

/**
 * One login attempt. On the MOBILE channel {@code deviceId} and {@code platform} identify the app
 * installation for trusted-device routing; {@code devicePublicKey} (P-256 JWK text) is optional and
 * stored for a later possession proof. {@code tokenEncryptionKey} is the app's public P-256 JWK as
 * JSON text; the sealer validates it. {@code captcha} is null unless the app solved one; it is
 * required once the identity has failed {@code LockoutPolicy.captchaAfter()} times.
 */
@Builder
public record LoginCommand(UserName userName, Password password, Channel channel, DeviceId deviceId,
                           DevicePlatform platform, String devicePublicKey, String tokenEncryptionKey,
                           CaptchaSolution captcha) {
    public LoginCommand {
        Objects.requireNonNull(userName, "userName");
        Objects.requireNonNull(password, "password");
        Objects.requireNonNull(channel, "channel");
        Objects.requireNonNull(tokenEncryptionKey, "tokenEncryptionKey");
        if (channel == Channel.MOBILE && (deviceId == null || platform == null)) {
            throw new IllegalArgumentException("A mobile login needs the device ID and platform");
        }
    }

    @Override
    public String toString() {
        return "LoginCommand[userName=" + userName + ", channel=" + channel + ", redacted]";
    }
}
