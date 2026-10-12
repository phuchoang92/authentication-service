package com.vpbank.dcp.infrastructure.adapter.in.web.password;

import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpHeaders;

/** Login headers are parsed independently of the JSON body. */
public final class PasswordLoginHeaders {
    private final UUID operationId;

    private PasswordLoginHeaders(UUID operationId) {
        this.operationId = operationId;
    }

    public static PasswordLoginHeaders from(HttpHeaders headers) {
        if (headers.containsHeader(HttpHeaders.AUTHORIZATION)
                || headers.containsHeader(HttpHeaders.CONTENT_ENCODING)) {
            throw new InvalidPasswordLoginRequestException();
        }
        String operation = single(headers, "Idempotency-Key", 36, 36);
        try {
            UUID operationId = UUID.fromString(operation);
            if (!operationId.toString().equals(operation)) {
                throw new InvalidPasswordLoginRequestException();
            }
            return new PasswordLoginHeaders(operationId);
        } catch (IllegalArgumentException invalid) {
            throw new InvalidPasswordLoginRequestException(invalid);
        }
    }

    private static String single(HttpHeaders headers, String name, int minimum, int maximum) {
        List<String> values = headers.get(name);
        if (values == null || values.size() != 1 || values.getFirst() == null
                || values.getFirst().length() < minimum || values.getFirst().length() > maximum
                || values.getFirst().isBlank()) {
            throw new InvalidPasswordLoginRequestException();
        }
        return values.getFirst();
    }

    public UUID operationId() { return operationId; }

    @Override
    public String toString() {
        return "PasswordLoginHeaders[redacted]";
    }
}
