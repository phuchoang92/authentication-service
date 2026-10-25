package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.port.out.CaptchaStore;
import com.vpbank.dcp.auth.domain.model.CaptchaAnswer;
import com.vpbank.dcp.auth.domain.model.CaptchaId;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/** Challenges by ID; consumed on first use, right or wrong; bound to one customer (or nobody). */
final class InMemoryCaptchaStore implements CaptchaStore {
    record Challenge(CustomerId customerId, String answer, Instant expiresAt) { }

    final Map<CaptchaId, Challenge> challenges = new HashMap<>();

    @Override
    public void save(CaptchaId id, CustomerId customerId, CaptchaAnswer answer, Instant expiresAt) {
        challenges.put(id, new Challenge(customerId, answer.normalized(), expiresAt));
    }

    @Override
    public boolean consume(CaptchaId id, CustomerId customerId, CaptchaAnswer answer) {
        Challenge challenge = challenges.remove(id);
        return challenge != null && customerId != null && customerId.equals(challenge.customerId())
                && challenge.answer().equals(answer.normalized());
    }
}
