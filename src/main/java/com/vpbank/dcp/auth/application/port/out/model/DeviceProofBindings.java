package com.vpbank.dcp.auth.application.port.out.model;

import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.DevicePlatform;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.UserName;
import java.util.Objects;

/**
 * The request values a login device proof must be bound to (slice 13): the proof names them in its
 * claims and the verifier refuses a proof made for any other login. {@code tokenEncryptionKey} is the
 * app's public JWK text; the proof carries its thumbprint.
 */
public record DeviceProofBindings(UserName userName, Channel channel, DeviceId deviceId, DevicePlatform platform,
                                  String tokenEncryptionKey) {
    public DeviceProofBindings {
        Objects.requireNonNull(userName, "userName");
        Objects.requireNonNull(channel, "channel");
        Objects.requireNonNull(deviceId, "deviceId");
        Objects.requireNonNull(platform, "platform");
        Objects.requireNonNull(tokenEncryptionKey, "tokenEncryptionKey");
    }

    @Override
    public String toString() {
        return "DeviceProofBindings[userName=" + userName + ", channel=" + channel + ", deviceId=" + deviceId + "]";
    }
}
