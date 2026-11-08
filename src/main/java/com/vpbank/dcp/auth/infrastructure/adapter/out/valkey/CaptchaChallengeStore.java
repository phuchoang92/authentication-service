package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

import com.vpbank.dcp.auth.application.port.out.model.CacheTransaction;
import com.vpbank.dcp.auth.application.port.out.model.TransactionKind;
import com.vpbank.dcp.auth.application.port.out.repository.CaptchaStore;
import com.vpbank.dcp.auth.application.port.out.repository.TransactionStore;
import com.vpbank.dcp.auth.domain.model.CaptchaAnswer;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/**
 * {@link CaptchaStore} as transactions of kind {@code captcha} in the shared {@link TransactionStore}, one per
 * customer (Valkey, one JSON STRING, forgotten at the expiry). {@code issue} overwrites the customer's record;
 * {@code consume} is read → remove-if-unchanged, so of two callers racing for the same challenge exactly one
 * removes it, and only that one compares the answer. The store keeps the keyed digest of the answer, never the
 * answer.
 */
@RequiredArgsConstructor
public final class CaptchaChallengeStore implements CaptchaStore {
    static final TransactionKind<CaptchaChallenge> KIND = new TransactionKind<>("captcha", CaptchaChallenge.class);

    @NonNull private final TransactionStore transactionStore;
    @NonNull private final CaptchaAnswerDigest captchaAnswerDigest;
    @NonNull private final Clock clock;

    @Override
    public void issue(CustomerId customerId, CaptchaAnswer answer, Instant expiresAt) {
        CaptchaChallenge challenge = new CaptchaChallenge(captchaAnswerDigest.of(answer));
        transactionStore.overwrite(KIND.open(customerId.value(), expiresAt, challenge));
    }

    @Override
    public boolean consume(CustomerId customerId, CaptchaAnswer answer) {
        Optional<CacheTransaction<CaptchaChallenge>> stored = transactionStore.find(KIND, customerId.value());
        if (stored.isEmpty()) {
            return false;
        }
        boolean consumedByThisCall = transactionStore.deleteIfCurrent(stored.get());
        if (!consumedByThisCall) {
            return false; // someone else consumed it first
        }
        return matches(stored.get(), answer);
    }

    /** Live at this moment and answered with exactly the stored answer. */
    private boolean matches(CacheTransaction<CaptchaChallenge> stored, CaptchaAnswer answer) {
        boolean live = stored.isOpen(clock.instant());
        boolean sameAnswer = MessageDigest.isEqual(
                stored.payload().answerDigest().getBytes(StandardCharsets.UTF_8),
                captchaAnswerDigest.of(answer).getBytes(StandardCharsets.UTF_8));
        return live && sameAnswer;
    }
}
