package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.response;

import java.util.UUID;

/** Contract §1 success body: the request that created (or already held) the login account. */
public record RegistrationResponse(UUID requestId, String customerId, String userName, String state) { }
