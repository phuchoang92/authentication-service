package com.vpbank.dcp.infrastructure.adapter.out.persistence.repository.password;

import java.util.Objects;

public record PasswordOperationProgressView(String state) {
    public PasswordOperationProgressView {
        Objects.requireNonNull(state);
    }
}
