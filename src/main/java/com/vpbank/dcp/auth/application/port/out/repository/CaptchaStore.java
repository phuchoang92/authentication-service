package com.vpbank.dcp.auth.application.port.out.repository;

import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.domain.model.CaptchaAnswer;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import java.time.Instant;

/**
 * Short-lived CAPTCHA challenges (Valkey), one open challenge per customer: issuing a new one replaces the
 * previous, and a challenge is consumed on first use, right or wrong. Throws {@link RepositoryUnavailableException}.
 */
public interface CaptchaStore {

    /** The customer's open challenge from now on; whatever challenge it had before is gone. */
    void issue(CustomerId customerId, CaptchaAnswer answer, Instant expiresAt);

    /** Removes the customer's challenge and tells whether it was live and answered correctly. */
    boolean consume(CustomerId customerId, CaptchaAnswer answer);
}
