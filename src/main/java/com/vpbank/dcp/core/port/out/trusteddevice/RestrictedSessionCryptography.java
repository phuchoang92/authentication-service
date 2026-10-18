package com.vpbank.dcp.core.port.out.trusteddevice;

import com.vpbank.dcp.core.domain.customer.SubjectId;
import com.vpbank.dcp.core.domain.security.Digest32;
import java.time.Instant;

/** Issues a random token for a restricted session and encrypts it to the login's Kenc. */
public interface RestrictedSessionCryptography {

    PreparedRestrictedSession prepare(RestrictedSession session, Instant expiresAt);

    /** The only form of the App device ID that is stored; compared on every later step. */
    Digest32 deviceIdDigest(SubjectId owner, String channel, String deviceId);
}
