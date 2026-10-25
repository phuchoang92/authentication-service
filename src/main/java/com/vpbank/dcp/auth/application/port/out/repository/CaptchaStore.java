package com.vpbank.dcp.auth.application.port.out.repository;

import com.vpbank.dcp.auth.domain.model.CaptchaAnswer;
import com.vpbank.dcp.auth.domain.model.CaptchaId;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import java.time.Instant;

/**
 * Short-lived CAPTCHA challenges (Valkey). A challenge is bound to the customer it was issued for
 * and is consumed on first use, right or wrong. Throws {@link RepositoryUnavailableException}.
 */
public interface CaptchaStore {

    /** {@code customerId} may be null for an unknown user name: the challenge then matches nobody. */
    void save(CaptchaId id, CustomerId customerId, CaptchaAnswer answer, Instant expiresAt);

    /** Removes the challenge and tells whether it was live, bound to this customer and answered correctly. */
    boolean consume(CaptchaId id, CustomerId customerId, CaptchaAnswer answer);
}
