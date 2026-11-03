package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.controller;

import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ServiceClientAssertionFilter;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ServiceTokenPublicKeys;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * BFF → Auth (slice 12): the public keys that verify service tokens, as a bare RFC 7517 JWK Set so a standard
 * JWKS client can read it. The only route without the {@code {success, data}} envelope; public, not gated.
 */
@RestController
@ConditionalOnProperty(prefix = "auth.service-token", name = "enabled", havingValue = "true")
@RequiredArgsConstructor
public class ServiceTokenJwksController {
    public static final String JWKS_PATH = ServiceClientAssertionFilter.ISSUE_PATH + "/jwks";

    @NonNull private final ServiceTokenPublicKeys serviceTokenPublicKeys;

    @GetMapping(path = JWKS_PATH, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> keys() {
        return ResponseEntity.ok(serviceTokenPublicKeys.json());
    }
}
