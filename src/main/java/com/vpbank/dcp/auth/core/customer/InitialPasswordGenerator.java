package com.vpbank.dcp.auth.core.customer;

import java.security.SecureRandom;
import java.util.Objects;

/**
 * Random first password sent by SMS: upper and lower letters and digits, at least one of each.
 * Look-alike characters (0/O, 1/l/I) are left out because the customer types it from an SMS.
 */
public final class InitialPasswordGenerator {
    private static final String UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ";
    private static final String LOWER = "abcdefghijkmnpqrstuvwxyz";
    private static final String DIGITS = "23456789";
    private static final String ALL = UPPER + LOWER + DIGITS;

    private final SecureRandom random;
    private final int length;

    public InitialPasswordGenerator(SecureRandom random, int length) {
        this.random = Objects.requireNonNull(random);
        if (length < 8 || length > 64) {
            throw new IllegalArgumentException("Initial password length must be 8 to 64");
        }
        this.length = length;
    }

    public String next() {
        char[] password = new char[length];
        password[0] = pick(UPPER);
        password[1] = pick(LOWER);
        password[2] = pick(DIGITS);
        for (int i = 3; i < length; i++) {
            password[i] = pick(ALL);
        }
        for (int i = length - 1; i > 0; i--) {
            int j = random.nextInt(i + 1);
            char swap = password[i];
            password[i] = password[j];
            password[j] = swap;
        }
        return new String(password);
    }

    private char pick(String alphabet) {
        return alphabet.charAt(random.nextInt(alphabet.length()));
    }
}
