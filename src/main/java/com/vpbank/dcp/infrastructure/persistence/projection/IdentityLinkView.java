package com.vpbank.dcp.infrastructure.persistence.projection;

/** Stored identity ownership and status; conflict handling belongs to the adapter. */
public record IdentityLinkView(String providerSubject, String status) {
    @Override
    public String toString() {
        return "IdentityLinkView[redacted]";
    }
}
