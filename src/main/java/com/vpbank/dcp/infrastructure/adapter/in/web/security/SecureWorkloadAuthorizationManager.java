package com.vpbank.dcp.infrastructure.adapter.in.web.security;

import java.util.function.Supplier;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

public final class SecureWorkloadAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {
    @Override
    public AuthorizationResult authorize(Supplier<? extends Authentication> authentication,
                                         RequestAuthorizationContext context) {
        Authentication workload = authentication.get();
        return new AuthorizationDecision(context.getRequest().isSecure() && workload != null
                && workload.isAuthenticated() && workload.getAuthorities().stream()
                .anyMatch(authority -> "WORKLOAD".equals(authority.getAuthority())));
    }
}
