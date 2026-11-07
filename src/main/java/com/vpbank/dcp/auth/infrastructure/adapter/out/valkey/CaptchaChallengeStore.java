package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

import com.vpbank.dcp.auth.application.port.out.model.CacheTransaction;
import com.vpbank.dcp.auth.application.port.out.model.TransactionKind;
import com.vpbank.dcp.auth.application.port.out.repository.CaptchaStore;
import com.vpbank.dcp.auth.application.port.out.repository.TransactionStore;
import com.vpbank.dcp.auth.domain.model.CaptchaAnswer;
import com.vpbank.dcp.auth.domain.model.CaptchaId;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/**
 * {@link CaptchaStore} as one-shot transactions of kind {@code captcha} in the shared {@link TransactionStore}
 * (Valkey, one JSON STRING per challenge, forgotten at the expiry). {@code consume} is read → remove-if-unchanged:
 * of two callers racing for the same challenge exactly one removes it, and only that one compares the answer.
 * The store keeps the keyed digest of the answer, never the answer.
 */
@RequiredArgsConstructor
public final class CaptchaChallengeStore implements CaptchaStore {
    static final TransactionKind<CaptchaChallenge> KIND = new TransactionKind<>("captcha", CaptchaChallenge.class);

    @NonNull private final TransactionStore transactionStore;
    @NonNull private final CaptchaAnswerDigest captchaAnswerDigest;
    @NonNull private final Clock clock;

    @Override
    public void save(CaptchaId id, CustomerId customerId, CaptchaAnswer answer, Instant expiresAt) {
        String boundCustomerId = customerId == null ? null : customerId.value();
        CaptchaChallenge challenge = new CaptchaChallenge(boundCustomerId, captchaAnswerDigest.of(answer));

        boolean created = transactionStore.createIfAbsent(KIND.open(id.value().toString(), expiresAt, challenge));
        if (!created) {
            // Challenge IDs are random UUIDs: an ID in use is a programming error, never something to overwrite.
            throw new IllegalStateException("A challenge with this ID already exists");
        }
    }

    @Override
    public boolean consume(CaptchaId id, CustomerId customerId, CaptchaAnswer answer) {
        Optional<CacheTransaction<CaptchaChallenge>> stored = transactionStore.find(KIND, id.value().toString());
        if (stored.isEmpty()) {
            return false;
        }
        boolean consumedByThisCall = transactionStore.deleteIfCurrent(stored.get());
        if (!consumedByThisCall) {
            return false; // someone else consumed it first
        }
        return matches(stored.get(), customerId, answer);
    }

    /** Live at this moment, issued for this customer, and answered with exactly the stored answer. */
    private boolean matches(CacheTransaction<CaptchaChallenge> stored, CustomerId customerId, CaptchaAnswer answer) {
        CaptchaChallenge challenge = stored.payload();
        boolean live = stored.isOpen(clock.instant());
        boolean sameOwner = customerId != null && customerId.value().equals(challenge.boundCustomerId());
        boolean sameAnswer = MessageDigest.isEqual(
                challenge.answerDigest().getBytes(StandardCharsets.UTF_8),
                captchaAnswerDigest.of(answer).getBytes(StandardCharsets.UTF_8));
        return live && sameOwner && sameAnswer;
    }
}
