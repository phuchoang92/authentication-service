package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.port.out.repository.CaptchaStore;
import com.vpbank.dcp.auth.domain.model.CaptchaAnswer;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/** One challenge per customer, replaced by the next; consumed on first use, right or wrong. */
final class InMemoryCaptchaStore implements CaptchaStore {
    record Challenge(String answer, Instant expiresAt) { }

    final Map<CustomerId, Challenge> challenges = new HashMap<>();
    boolean unavailable;

    @Override
    public void issue(CustomerId customerId, CaptchaAnswer answer, Instant expiresAt) {
        if (unavailable) {
            throw new RepositoryUnavailableException(new RuntimeException("down"));
        }
        challenges.put(customerId, new Challenge(answer.normalized(), expiresAt));
    }

    @Override
    public boolean consume(CustomerId customerId, CaptchaAnswer answer) {
        Challenge challenge = challenges.remove(customerId);
        return challenge != null && challenge.answer().equals(answer.normalized());
    }
}
