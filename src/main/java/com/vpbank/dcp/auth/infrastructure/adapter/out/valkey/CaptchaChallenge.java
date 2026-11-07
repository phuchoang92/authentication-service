package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

import lombok.NonNull;

/**
 * What a stored CAPTCHA challenge holds: the customer it was issued for ({@code null} for an unknown user name,
 * so it matches nobody) and the keyed digest of its answer, never the answer. Its deadline is the transaction's.
 */
public record CaptchaChallenge(String boundCustomerId, @NonNull String answerDigest) {
}
