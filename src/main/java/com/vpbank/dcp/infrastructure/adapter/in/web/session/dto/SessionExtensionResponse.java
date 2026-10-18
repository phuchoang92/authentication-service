package com.vpbank.dcp.infrastructure.adapter.in.web.session.dto;

/** Flow 16 success body; instants are ISO-8601 UTC strings. */
public record SessionExtensionResponse(String status, String idleExpiresAt, String absoluteExpiresAt) {
}
