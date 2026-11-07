package com.vpbank.dcp.auth.domain.model;

import java.util.regex.Pattern;
import lombok.NonNull;

/** E.164 phone number: a plus sign and 8 to 15 digits. */
public record PhoneNumber(@NonNull String value) {
    private static final Pattern FORMAT = Pattern.compile("\\+[1-9][0-9]{7,14}");

    public PhoneNumber {
        if (!FORMAT.matcher(value).matches()) {
            throw new IllegalArgumentException("Phone number is not E.164");
        }
    }

    /** Personal data: never printed. */
    @Override
    public String toString() {
        return "PhoneNumber[redacted]";
    }
}
