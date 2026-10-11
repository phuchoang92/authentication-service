package com.vpbank.dcp.core.port.out.keycloak;

import java.util.Objects;

/** Plaintext exists only for the bounded App→BFF→Auth→Keycloak credential exchange. */
public final class PasswordVerification {

    private final String username;
    private final String password;

    public PasswordVerification(String username, String password) {
        this.username = Objects.requireNonNull(username, "username");
        this.password = Objects.requireNonNull(password, "password");
        if (username.isBlank() || password.isEmpty()) {
            throw new InvalidPasswordVerificationException();
        }
    }

    public String username() {
        return username;
    }

    public String password() {
        return password;
    }

    @Override
    public String toString() {
        return "PasswordVerification[redacted]";
    }
}
