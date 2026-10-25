package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.port.in.RegisterCustomerCommand;
import com.vpbank.dcp.auth.domain.model.RequestDigest;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Objects;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * HMAC-SHA256 of a registration request with a server key. A plain hash would let anyone with
 * database access guess the phone number back; the key prevents that.
 */
public final class RequestDigester {
    private static final String ALGORITHM = "HmacSHA256";
    private final byte[] key;

    public RequestDigester(byte[] key) {
        Objects.requireNonNull(key, "key");
        if (key.length < 32) {
            throw new IllegalArgumentException("Request digest key must be at least 32 bytes");
        }
        this.key = key.clone();
    }

    public RequestDigest digest(RegisterCustomerCommand command) {
        // Length-prefixed fields: "ab"+"c" and "a"+"bc" give different input.
        StringBuilder canonical = new StringBuilder();
        for (String field : new String[]{command.customerId().value(), command.userName().value(),
                command.firstName(), command.lastName(), command.phoneNumber().value(),
                command.email() == null ? "" : command.email().value()}) {
            canonical.append(field.length()).append(':').append(field).append(';');
        }
        try {
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(new SecretKeySpec(key, ALGORITHM));
            return new RequestDigest(mac.doFinal(canonical.toString().getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException failure) {
            throw new IllegalStateException("HmacSHA256 is not available", failure);
        }
    }
}
