package com.vpbank.dcp.infrastructure.adapter.in.web;

import java.net.URI;
import java.util.Objects;

/**
 * Constructs the public DPoP target from trusted startup configuration and a validated path.
 */
public final class ExternalUriPolicy {

    private final URI origin;

    public ExternalUriPolicy(String configuredOrigin) {
        Objects.requireNonNull(configuredOrigin, "configuredOrigin");
        URI parsed = URI.create(configuredOrigin);
        if (!"https".equalsIgnoreCase(parsed.getScheme()) || parsed.getHost() == null
                || parsed.getUserInfo() != null || parsed.getRawQuery() != null
                || parsed.getRawFragment() != null || !"".equals(parsed.getRawPath())) {
            throw new InvalidExternalUriException();
        }
        this.origin = parsed;
    }

    public URI forPath(String rawPath) {
        Objects.requireNonNull(rawPath, "rawPath");
        if (!rawPath.startsWith("/") || rawPath.length() > 2048
                || rawPath.contains("?") || rawPath.contains("#")
                || rawPath.contains("\\") || rawPath.contains("%")
                || hasDotSegment(rawPath)) {
            throw new InvalidExternalUriException();
        }
        try {
            return URI.create(origin.toASCIIString() + rawPath);
        } catch (IllegalArgumentException failure) {
            throw new InvalidExternalUriException(failure);
        }
    }

    private boolean hasDotSegment(String path) {
        for (String segment : path.split("/", -1)) {
            if (".".equals(segment) || "..".equals(segment)) {
                return true;
            }
        }
        return false;
    }
}
