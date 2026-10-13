package com.vpbank.dcp.infrastructure.persistence.projection;

import java.util.UUID;

public record TrustedDeviceAppView(UUID primaryBindingId, long version) { }
