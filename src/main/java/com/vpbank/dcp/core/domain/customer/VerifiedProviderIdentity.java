package com.vpbank.dcp.core.domain.customer;

import java.net.URI;

/** Identity accepted only after verifying the signed Keycloak credential result. */
public record VerifiedProviderIdentity(String issuer, String subject) {

    public VerifiedProviderIdentity {
        if (issuer == null || subject == null || subject.isBlank() || subject.length() > 255
                || issuer.length() > 255) {
            throw new InvalidCustomerStateException();
        }
        try {
            URI parsed = URI.create(issuer);
            if (!"https".equals(parsed.getScheme()) || parsed.getHost() == null
                    || parsed.getUserInfo() != null || parsed.getRawFragment() != null) {
                throw new InvalidCustomerStateException();
            }
        } catch (IllegalArgumentException failure) {
            throw new InvalidCustomerStateException();
        }
    }
}
