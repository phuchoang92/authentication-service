package com.vpbank.dcp.core.domain.device;

import java.util.Objects;
import java.util.UUID;

/**
 * Identifies one customer-to-device trust binding.
 *
 * <p>A separate type because a binding id and an owner id are both UUIDs and sat next to each
 * other in several signatures, where swapping them compiled silently and broke the ownership
 * guard. They can no longer be interchanged.
 */
public record BindingId(UUID value) {
    public BindingId {
        Objects.requireNonNull(value, "value");
    }

    @Override
    public String toString() {
        return value.toString();
    }
}
