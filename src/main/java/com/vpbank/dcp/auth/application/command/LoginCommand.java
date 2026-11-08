package com.vpbank.dcp.auth.application.command;

import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.DevicePlatform;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.CaptchaAnswer;
import com.vpbank.dcp.auth.domain.model.DeviceProof;
import com.vpbank.dcp.auth.domain.model.Password;
import com.vpbank.dcp.auth.domain.model.UserName;
import lombok.Builder;
import lombok.NonNull;

/**
 * One login attempt. On the MOBILE channel {@code deviceId} and {@code platform} identify the app
 * installation for trusted-device routing; {@code deviceProof} is what a trusted device signs with its
 * key for this login (slice 13), null when the app sent none. {@code tokenEncryptionKey} is the app's public P-256 JWK as
 * JSON text; the sealer validates it. {@code captchaAnswer} is null unless the app answers the challenge a
 * previous login handed out; one is required once the identity has failed {@code LockoutPolicy.captchaAfter()}
 * times.
 */
@Builder
public record LoginCommand(@NonNull UserName userName,
                           @NonNull Password password,
                           @NonNull Channel channel,
                           DeviceId deviceId,
                           DevicePlatform platform,
                           DeviceProof deviceProof,
                           @NonNull String tokenEncryptionKey,
                           CaptchaAnswer captchaAnswer) {
    public LoginCommand {
        if (channel == Channel.MOBILE && (deviceId == null || platform == null)) {
            throw new IllegalArgumentException("A mobile login needs the device ID and platform");
        }
    }

    @Override
    public String toString() {
        return "LoginCommand[userName=" + userName + ", channel=" + channel + ", redacted]";
    }
}
