package com.vpbank.dcp.auth.application.command;

import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.SessionId;
import lombok.Builder;
import lombok.NonNull;

/**
 * A flow asks for a new session (login, the primary enrollment, the approval claim): its ID, whose it is, on which
 * channel and installation, and the app's public key the token envelope is sealed to. {@code deviceId} is null on
 * WEB, which has no installation.
 */
@Builder
public record IssueSessionCommand(@NonNull SessionId sessionId,
                                  @NonNull CustomerId customerId,
                                  @NonNull Channel channel,
                                  DeviceId deviceId,
                                  @NonNull String tokenEncryptionKey) {
    @Override
    public String toString() {
        return "IssueSessionCommand[sessionId=" + sessionId + ", channel=" + channel + ", redacted]";
    }
}
