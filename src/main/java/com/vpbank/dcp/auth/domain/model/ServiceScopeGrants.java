package com.vpbank.dcp.auth.domain.model;

import com.vpbank.dcp.auth.domain.enums.ServiceScope;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.NonNull;

/**
 * Which scopes each internal service may ask a token for (slice 12). Values arrive validated from configuration;
 * a service that is not listed, or a scope it is not granted, is refused. Immutable: the map and its sets are
 * copied.
 */
public record ServiceScopeGrants(@NonNull Map<ServiceId, Set<ServiceScope>> grants) {
    public ServiceScopeGrants {
        grants = Map.copyOf(grants.entrySet().stream()
                .collect(Collectors.toUnmodifiableMap(Map.Entry::getKey, entry -> Set.copyOf(entry.getValue()))));
    }

    public boolean allows(@NonNull ServiceId callingService, @NonNull ServiceScope scope) {
        return grants.getOrDefault(callingService, Set.of()).contains(scope);
    }
}
