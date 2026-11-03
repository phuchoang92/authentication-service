package com.vpbank.dcp.auth.domain.model;

import com.vpbank.dcp.auth.domain.enums.ServiceScope;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Which scopes each internal service may ask a token for (slice 12). Values arrive validated from configuration;
 * a service that is not listed, or a scope it is not granted, is refused. Immutable: the map and its sets are
 * copied.
 */
public record ServiceScopeGrants(Map<ServiceId, Set<ServiceScope>> grants) {
    public ServiceScopeGrants {
        Objects.requireNonNull(grants, "grants");
        grants = Map.copyOf(grants.entrySet().stream()
                .collect(Collectors.toUnmodifiableMap(Map.Entry::getKey, entry -> Set.copyOf(entry.getValue()))));
    }

    public boolean allows(ServiceId caller, ServiceScope scope) {
        Objects.requireNonNull(caller, "caller");
        Objects.requireNonNull(scope, "scope");
        return grants.getOrDefault(caller, Set.of()).contains(scope);
    }
}
