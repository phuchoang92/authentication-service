package com.vpbank.dcp.infrastructure.adapter.in.web.mfa;

import com.vpbank.dcp.core.domain.security.RequestKeyThumbprint;
import com.vpbank.dcp.core.port.in.mfa.TotpLoginCommand;
import com.vpbank.dcp.core.port.out.pending.PendingTotpLogin;
import com.vpbank.dcp.core.port.out.pending.PendingTotpStore;
import com.vpbank.dcp.core.port.out.pending.PendingTotpUnavailableException;
import com.vpbank.dcp.core.port.out.pending.PendingTokenLookup;
import com.vpbank.dcp.core.port.out.pending.InvalidPendingTokenException;
import com.vpbank.dcp.core.port.out.security.DpopExpectation;
import com.vpbank.dcp.core.port.out.security.DpopProofDecoder;
import com.vpbank.dcp.core.port.out.security.InvalidDpopProofException;
import com.vpbank.dcp.core.port.out.session.SessionTokenLookup;
import com.vpbank.dcp.infrastructure.adapter.in.web.ExternalUriPolicy;
import java.net.URI;
import java.time.Clock;
import java.util.Objects;

/** Binds the pending token, DPoP ath/nonce, challenge and App key before the use case. */
public final class TotpLoginRequestVerifier {
    private final PendingTokenLookup lookup;
    private final PendingTotpStore pending;
    private final DpopProofDecoder dpop;
    private final ExternalUriPolicy uris;
    private final Clock clock;

    public TotpLoginRequestVerifier(PendingTokenLookup lookup, PendingTotpStore pending, DpopProofDecoder dpop,
                                    ExternalUriPolicy uris, Clock clock) {
        this.lookup = Objects.requireNonNull(lookup);
        this.pending = Objects.requireNonNull(pending);
        this.dpop = Objects.requireNonNull(dpop);
        this.uris = Objects.requireNonNull(uris);
        this.clock = Objects.requireNonNull(clock);
    }

    public TotpLoginCommand verify(String challengeId, String authorization,
                                   String dpopHeader, String proofEnvelope) {
        if (challengeId == null || !challengeId.matches("[A-Za-z0-9_-]{22,64}")
                || authorization == null || !authorization.startsWith("DPoP ")
                || dpopHeader == null || dpopHeader.length() < 64 || dpopHeader.length() > 4096) {
            throw new InvalidTotpLoginRequestException();
        }
        String exactToken = authorization.substring(5);
        if (exactToken.length() > 128 || exactToken.isBlank()) {
            throw new InvalidTotpLoginRequestException();
        }
        try {
            SessionTokenLookup token = lookup.forExactToken(exactToken);
            PendingTotpLogin login = pending.find(token).orElse(null);
            if (login == null || !challengeId.equals(login.challenge().challengeId())) {
                throw new InvalidTotpLoginRequestException();
            }
            URI publicUri = uris.forPath("/api/mfa/challenges/" + challengeId + "/verify");
            var expected = DpopExpectation.forToken("POST", publicUri,
                    new RequestKeyThumbprint(com.vpbank.dcp.core.domain.security.Digest32.fromBase64Url(
                            login.keys().requestKeyJkt())), challengeId, exactToken, clock.instant());
            var verified = dpop.verify(dpopHeader, expected);
            return new TotpLoginCommand(challengeId, token, verified, proofEnvelope, clock.instant());
        } catch (InvalidPendingTokenException | InvalidDpopProofException failure) {
            throw new InvalidTotpLoginRequestException();
        } catch (PendingTotpUnavailableException failure) {
            throw new TotpLoginRequestUnavailableException();
        }
    }
}
