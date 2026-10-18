package com.vpbank.dcp.core.application.session;

import com.vpbank.dcp.core.domain.customer.InvalidCustomerFreshnessPolicyException;
import com.vpbank.dcp.core.domain.session.SessionAssurance;
import com.vpbank.dcp.core.domain.session.SessionDeadlines;
import com.vpbank.dcp.core.port.in.session.IssueLoginSessionUseCase;
import com.vpbank.dcp.core.port.in.session.LoginConfirmation;
import com.vpbank.dcp.core.port.in.session.SessionLoginEvidence;
import com.vpbank.dcp.core.port.in.session.SessionLoginResult;
import com.vpbank.dcp.core.port.out.session.CustomerStatusFreshness;
import com.vpbank.dcp.core.port.out.session.LoginSessionSecurity;
import com.vpbank.dcp.core.port.out.session.LoginSessionSecurityStore;
import com.vpbank.dcp.core.port.out.session.LoginSessionSecurityUnavailableException;
import com.vpbank.dcp.core.port.out.session.PreparedSession;
import com.vpbank.dcp.core.port.out.session.SessionActivationContext;
import com.vpbank.dcp.core.port.out.session.SessionActivationSnapshot;
import com.vpbank.dcp.core.port.out.session.SessionApplyResult;
import com.vpbank.dcp.core.port.out.session.SessionAuthority;
import com.vpbank.dcp.core.port.out.session.SessionCryptography;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Integration-only issuance after Customer and binding are checked around Redis publication. */
public final class IssueLoginSessionService implements IssueLoginSessionUseCase {
    private final LoginSessionSecurityStore security;
    private final SessionCryptography cryptography;
    private final SessionAuthority authority;
    private final Duration customerStatusMaximumAge;

    public IssueLoginSessionService(LoginSessionSecurityStore security,
                                    SessionCryptography cryptography,
                                    SessionAuthority authority,
                                    Duration customerStatusMaximumAge) {
        this.security = Objects.requireNonNull(security);
        this.cryptography = Objects.requireNonNull(cryptography);
        this.authority = Objects.requireNonNull(authority);
        this.customerStatusMaximumAge = Objects.requireNonNull(customerStatusMaximumAge);
        if (customerStatusMaximumAge.isNegative() || customerStatusMaximumAge.isZero()) {
            throw new InvalidCustomerFreshnessPolicyException();
        }
    }

    @Override
    public SessionLoginResult issue(UUID operationId, Instant now, SessionLoginEvidence evidence) {
        Objects.requireNonNull(operationId);
        Objects.requireNonNull(now);
        Objects.requireNonNull(evidence);
        LoginSessionSecurity before = current(evidence);
        if (before == null) {
            return new SessionLoginResult.Unavailable();
        }
        if (eligible(before, evidence, now)) {
            return new SessionLoginResult.Rejected();
        }
        UUID generation = authority.currentGeneration().orElse(null);
        if (generation == null || !generation.equals(evidence.generation())) {
            return new SessionLoginResult.Unavailable();
        }
        SessionActivationSnapshot snapshot = snapshot(operationId, evidence, before);
        PreparedSession prepared = cryptography.prepare(snapshot, generation,
                SessionDeadlines.createdAt(now), now.plusSeconds(120));
        if (authority.apply(prepared) != SessionApplyResult.APPLIED) {
            // A non-atomic Redis write may have left a partial candidate behind.
            authority.revoke(prepared);
            return new SessionLoginResult.Unavailable();
        }
        LoginSessionSecurity after = current(evidence);
        if (after == null || !after.equals(before) || eligible(after, evidence, now)
                || !authority.deliverable(prepared)) {
            authority.revoke(prepared);
            return new SessionLoginResult.Unavailable();
        }
        return new SessionLoginResult.Active(prepared);
    }

    private LoginSessionSecurity current(SessionLoginEvidence evidence) {
        try {
            return security.current(evidence.subject(), evidence.device().bindingId(),
                    evidence.device().channel()).orElse(null);
        } catch (LoginSessionSecurityUnavailableException failure) {
            return null;
        }
    }

    private boolean eligible(LoginSessionSecurity current, SessionLoginEvidence evidence, Instant now) {
        Instant customerDeadline = evidence.customer().checkedAt().plus(customerStatusMaximumAge);
        boolean primaryAllowed = evidence.confirmation() != LoginConfirmation.PRIMARY_PASSWORD
                || current.device().primary();
        return !current.customer().eligible() || !current.device().active() || !primaryAllowed
                || !now.isBefore(current.device().expiresAt())
                || !now.isBefore(customerDeadline)
                || current.customer().statusVersion() != evidence.customer().statusVersion()
                || current.versions().deviceSecurityVersion() != evidence.device().securityVersion();
    }

    private SessionActivationSnapshot snapshot(UUID operationId, SessionLoginEvidence evidence,
                                               LoginSessionSecurity current) {
        return new SessionActivationSnapshot(
                new SessionActivationContext(operationId, evidence.subject(),
                        evidence.device().channel(), evidence.device().bindingId()),
                evidence.keys(),
                current.versions(),
                new CustomerStatusFreshness(current.customer().statusVersion(),
                        evidence.customer().checkedAt().plus(customerStatusMaximumAge)),
                new SessionAssurance(SessionAssurance.DevicePossession.MFA_KEY_POSSESSION,
                        SessionAssurance.PlatformEvidence.NONE,
                        SessionAssurance.BiometricEnforcement.NOT_APPLICABLE),
                current.biometricEnabled());
    }
}
