package com.vpbank.dcp.core.session;


import java.time.Instant;
import java.util.UUID;

/**
 * Issues a random token and encrypts it to frozen Kenc; never persists plaintext.
 */
public interface SessionCryptography {
    PreparedSession prepare(SessionActivationSnapshot snapshot, UUID generation,
                            SessionDeadlines deadlines, Instant deliveryDeadline);
}
