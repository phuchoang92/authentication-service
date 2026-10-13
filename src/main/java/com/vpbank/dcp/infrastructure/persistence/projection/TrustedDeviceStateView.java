package com.vpbank.dcp.infrastructure.persistence.projection;

import java.util.Objects;

public record TrustedDeviceStateView(String status, long version, long deviceSecurityVersion) {
    public TrustedDeviceStateView {
        Objects.requireNonNull(status, "status");
    }
}
