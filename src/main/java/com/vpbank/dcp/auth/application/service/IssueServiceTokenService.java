package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.command.IssueServiceTokenCommand;
import com.vpbank.dcp.auth.application.port.in.IssueServiceTokenUseCase;
import com.vpbank.dcp.auth.application.port.out.gateway.ServiceTokenSigner;
import com.vpbank.dcp.auth.application.port.out.model.SecurityAuditEvent;
import com.vpbank.dcp.auth.application.port.out.repository.SecurityAuditStore;
import com.vpbank.dcp.auth.application.result.IssueServiceTokenResult;
import com.vpbank.dcp.auth.domain.enums.SecurityEventReason;
import com.vpbank.dcp.auth.domain.model.ServiceScopeGrants;
import com.vpbank.dcp.auth.domain.model.ServiceTokenClaims;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

import java.time.Clock;
import java.time.Instant;
import java.util.UUID;
import java.util.function.Supplier;

/**
 * Issues a scoped service token (slice 12): is the caller granted the scope, does the scope have the journey
 * reference it needs, then build the claims and sign. A reference sent for a scope that does not take one is
 * left out of the token. Stateless: nothing is stored, so there is nothing to fail on but the signer, and the
 * signer only fails on a broken key, which is a startup problem. Each outcome is handed to the activity audit
 * after it is decided (the store never blocks or throws).
 */
@RequiredArgsConstructor
public final class IssueServiceTokenService implements IssueServiceTokenUseCase {
    @NonNull
    private final ServiceScopeGrants grants;
    @NonNull
    private final ServiceTokenSigner serviceTokenSigner;
    @NonNull
    private final Supplier<UUID> tokenIds;
    @NonNull
    private final ServiceTokenSettings settings;
    @NonNull
    private final SecurityAuditStore securityAuditStore;
    @NonNull
    private final Clock clock;

    @Override
    public IssueServiceTokenResult issue(IssueServiceTokenCommand command) {
        if (!grants.allows(command.caller(), command.scope())) {
            securityAuditStore.record(auditEvent(command, SecurityEventReason.SCOPE_NOT_GRANTED, null));
            return new IssueServiceTokenResult.ScopeNotAllowed();
        }
        if (command.scope().businessReferenceRequired() && command.businessReference() == null) {
            securityAuditStore.record(auditEvent(command, SecurityEventReason.BUSINESS_REFERENCE_MISSING, null));
            return new IssueServiceTokenResult.BusinessReferenceRequired();
        }

        Instant now = clock.instant();
        ServiceTokenClaims claims = ServiceTokenClaims.builder()
                .issuer(settings.issuer())
                .caller(command.caller())
                .audience(settings.audience())
                .scope(command.scope())
                .businessReference(command.scope().businessReferenceRequired() ? command.businessReference() : null)
                .issuedAt(now)
                .expiresAt(now.plus(settings.lifetime()))
                .tokenId(tokenIds.get())
                .build();
        String token = serviceTokenSigner.sign(claims);
        securityAuditStore.record(auditEvent(command, SecurityEventReason.TOKEN_ISSUED, claims.tokenId()));
        return new IssueServiceTokenResult.Issued(token, claims.scope(), claims.expiresAt());
    }

    /**
     * Identifiers only: the service, the scope and the token ID; never the token or the business reference.
     */
    private SecurityAuditEvent auditEvent(IssueServiceTokenCommand command, SecurityEventReason reason, UUID tokenId) {
        return SecurityAuditEvent.builder()
                .reason(reason)
                .serviceId(command.caller())
                .scope(command.scope())
                .tokenId(tokenId)
                .occurredAt(clock.instant())
                .build();
    }
}
