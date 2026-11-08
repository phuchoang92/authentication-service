package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

import lombok.NonNull;

/**
 * What a stored CAPTCHA challenge holds: the keyed digest of its answer, never the answer. The customer it belongs
 * to is the transaction's ID, its deadline the transaction's.
 */
public record CaptchaChallenge(@NonNull String answerDigest) {
}
