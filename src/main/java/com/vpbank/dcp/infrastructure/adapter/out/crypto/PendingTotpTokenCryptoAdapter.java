package com.vpbank.dcp.infrastructure.adapter.out.crypto;

import com.nimbusds.jose.jwk.ECKey;
import com.vpbank.dcp.core.domain.security.LookupKeyVersion;
import com.vpbank.dcp.core.port.out.pending.PendingTokenCryptography;
import com.vpbank.dcp.core.port.out.pending.PendingTotpLogin;
import com.vpbank.dcp.core.port.out.pending.PreparedPendingToken;
import com.vpbank.dcp.core.port.out.session.SessionTokenLookup;
import java.text.ParseException;
import java.util.Objects;

/** Issues the restricted opaque DPoP token; its clear value is not returned to core or App. */
public final class PendingTotpTokenCryptoAdapter implements PendingTokenCryptography {
    private final BankingTokenIssuer tokens;
    private final TokenLookupHasher lookup;
    private final BankingTokenEnvelopeIssuer envelopes;
    private final LookupKeyVersion lookupVersion;

    public PendingTotpTokenCryptoAdapter(BankingTokenIssuer tokens, TokenLookupHasher lookup,
                                         BankingTokenEnvelopeIssuer envelopes,
                                         LookupKeyVersion lookupVersion) {
        this.tokens = Objects.requireNonNull(tokens);
        this.lookup = Objects.requireNonNull(lookup);
        this.envelopes = Objects.requireNonNull(envelopes);
        this.lookupVersion = Objects.requireNonNull(lookupVersion);
    }

    @Override
    public PreparedPendingToken issue(PendingTotpLogin pending) {
        Objects.requireNonNull(pending);
        try {
            OpaqueBankingToken token = tokens.issue();
            var context = new TokenDeliveryContext(pending.identity().operationId(),
                    pending.identity().channel(), BankingTokenStatus.PENDING_MFA,
                    pending.keys().requestKeyJkt(), pending.keys().deviceKeyJkt(),
                    pending.challenge().expiresAt());
            EncryptedBankingToken delivery = envelopes.issue(token,
                    ECKey.parse(pending.keys().responsePublicJwk()), context);
            return new PreparedPendingToken(new SessionTokenLookup(lookupVersion,
                    lookup.digest(token.exactValue())), delivery.tokenEnvelope(), delivery.receipt());
        } catch (ParseException failure) {
            throw new InvalidCryptographicInputException(failure);
        }
    }
}
