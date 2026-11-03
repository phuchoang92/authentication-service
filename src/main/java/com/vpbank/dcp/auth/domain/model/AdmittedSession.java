package com.vpbank.dcp.auth.domain.model;

import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.SessionStatus;
import java.util.Objects;

/**
 * The caller of a trusted-device route as the BFF admitted it (slice 11): the BFF has already checked the
 * session token, its status and its deadlines, and tells Auth whose session it is in a signed assertion.
 * Auth does not read the session to learn who is calling; it only decides whether this kind of session may
 * use the route. {@code status} is the kind of session the BFF saw: ACTIVE or NEED_TRUSTED_DEVICE, never ENDED.
 */
public record AdmittedSession(SessionId sessionId, CustomerId customerId, Channel channel, DeviceId deviceId,
                              SessionStatus status) {
    public AdmittedSession {
        Objects.requireNonNull(sessionId, "sessionId");
        Objects.requireNonNull(customerId, "customerId");
        Objects.requireNonNull(channel, "channel");
        Objects.requireNonNull(deviceId, "deviceId");
        Objects.requireNonNull(status, "status");
        if (!status.live()) {
            throw new IllegalArgumentException("An admitted session is live");
        }
    }

    /** A NEED_TRUSTED_DEVICE session: the device still needs trust (request, init, verify, confirm, claim). */
    public boolean restricted() {
        return status == SessionStatus.NEED_TRUSTED_DEVICE;
    }

    /** An ACTIVE session: the device is trusted (pending list, approve, authorize). */
    public boolean full() {
        return status.full();
    }
}
