package com.vpbank.dcp.infrastructure.adapter.out.http;

import java.net.URI;
import java.time.Duration;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/** Required connection limits and allowed routes for one external service. */
public record ExternalHttpSettings(URI origin, Duration deadline, int maximumResponseBytes,
                                   Set<Route> allowedRoutes) {

    public ExternalHttpSettings {
        Objects.requireNonNull(origin, "origin");
        Objects.requireNonNull(deadline, "deadline");
        allowedRoutes = Set.copyOf(allowedRoutes);
    }

    public record Route(String method, Pattern path) {
        public Route {
            Objects.requireNonNull(method, "method");
            Objects.requireNonNull(path, "path");
        }

        public static Route exact(String method, String path) {
            return new Route(method, Pattern.compile(Pattern.quote(path)));
        }

        BoundedJsonExchange.AllowedEndpoint allowed() {
            return new BoundedJsonExchange.AllowedEndpoint(method, path);
        }
    }
}
