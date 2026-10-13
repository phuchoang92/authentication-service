package com.vpbank.dcp.core.domain.totp;

import java.util.Arrays;
import java.util.Objects;

/**
 * Short-lived sensitive input; callers must close it after verification.
 */
public final class TotpCode implements AutoCloseable {
    private final char[] digits;

    public TotpCode(char[] digits) {
        Objects.requireNonNull(digits, "digits");
        if (digits.length != 6) {
            throw new InvalidTotpCodeException();
        }
        for (char digit : digits) {
            if (digit < '0' || digit > '9') {
                throw new InvalidTotpCodeException();
            }
        }
        this.digits = digits.clone();
    }

    public char[] copyDigits() {
        return digits.clone();
    }

    @Override
    public void close() {
        Arrays.fill(digits, '\0');
    }

    @Override
    public String toString() {
        return "TotpCode[redacted]";
    }
}
