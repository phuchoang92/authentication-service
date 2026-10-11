package com.vpbank.dcp.core.port.out.session;

import com.vpbank.dcp.core.domain.session.SessionDeadlines;
import java.time.Instant;
import java.util.UUID;

/** Issues a random token and encrypts it to frozen Kenc; never persists plaintext. */
public interface PasswordSessionCryptography {
    PreparedPasswordSession prepare(PasswordSessionFacts facts, UUID generation,
                                    SessionDeadlines deadlines, Instant deliveryDeadline);
}
