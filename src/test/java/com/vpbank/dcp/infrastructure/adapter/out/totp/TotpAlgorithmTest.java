package com.vpbank.dcp.infrastructure.adapter.out.totp;

import static org.assertj.core.api.Assertions.assertThat;

import com.vpbank.dcp.core.domain.totp.TotpCode;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class TotpAlgorithmTest {
    private static final byte[] RFC_SECRET = "12345678901234567890".getBytes(StandardCharsets.US_ASCII);
    private final TotpAlgorithm algorithm = new TotpAlgorithm();

    @Test
    void followsRfc6238Sha1SixDigitVector() {
        assertThat(algorithm.codeForStep(RFC_SECRET, 1)).isEqualTo("287082".toCharArray());
        try (TotpCode code = new TotpCode("287082".toCharArray())) {
            assertThat(algorithm.matchingStep(RFC_SECRET, code, Instant.ofEpochSecond(59)))
                    .isEqualTo(1);
        }
    }

    @Test
    void acceptsOneStepEitherSideButRejectsTwoOrFive() {
        char[] digits = algorithm.codeForStep(RFC_SECRET, 100);
        try (TotpCode code = new TotpCode(digits)) {
            assertThat(algorithm.matchingStep(RFC_SECRET, code, Instant.ofEpochSecond(99 * 30L)))
                    .isEqualTo(100);
            assertThat(algorithm.matchingStep(RFC_SECRET, code, Instant.ofEpochSecond(101 * 30L)))
                    .isEqualTo(100);
            assertThat(algorithm.matchingStep(RFC_SECRET, code, Instant.ofEpochSecond(98 * 30L)))
                    .isEqualTo(-1);
            assertThat(algorithm.matchingStep(RFC_SECRET, code, Instant.ofEpochSecond(102 * 30L)))
                    .isEqualTo(-1);
            assertThat(algorithm.matchingStep(RFC_SECRET, code, Instant.ofEpochSecond(95 * 30L)))
                    .isEqualTo(-1);
            assertThat(algorithm.matchingStep(RFC_SECRET, code, Instant.ofEpochSecond(105 * 30L)))
                    .isEqualTo(-1);
        }
    }
}
