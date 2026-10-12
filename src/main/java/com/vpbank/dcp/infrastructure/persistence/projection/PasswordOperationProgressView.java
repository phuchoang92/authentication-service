package com.vpbank.dcp.infrastructure.persistence.projection;

import java.util.Objects;

public record PasswordOperationProgressView(String state) {
    public PasswordOperationProgressView {
        Objects.requireNonNull(state);
    }
}
