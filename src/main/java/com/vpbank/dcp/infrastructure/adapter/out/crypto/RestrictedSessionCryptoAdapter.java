package com.vpbank.dcp.infrastructure.adapter.out.crypto;

import com.nimbusds.jose.jwk.ECKey;
import com.vpbank.dcp.core.domain.customer.SubjectId;
import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.LookupKeyVersion;
import com.vpbank.dcp.core.port.out.session.SessionTokenLookup;
import com.vpbank.dcp.core.port.out.trusteddevice.PreparedRestrictedSession;
import com.vpbank.dcp.core.port.out.trusteddevice.RestrictedSession;
import com.vpbank.dcp.core.port.out.trusteddevice.RestrictedSessionCryptography;
import com.vpbank.dcp.core.port.out.trusteddevice.TrustTarget;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * Issues the restricted token exactly like an ACTIVE one: random token, keyed lookup, Kenc JWE
 * and signed receipt. Only the receipt status differs, so the App cannot mistake it for ACTIVE.
 */
public final class RestrictedSessionCryptoAdapter implements RestrictedSessionCryptography {
    private static final String DEVICE_ID_DIGEST_LABEL = "RESTRICTED_SESSION_DEVICE_ID_V1";

    private final BankingTokenIssuer tokens;
    private final TokenLookupHasher lookup;
    private final BankingTokenEnvelopeIssuer envelopes;
    private final LookupKeyVersion lookupVersion;
    private final LengthPrefixedSigningInputEncoder encoding;
    private final Sha256Digests digests;

    public RestrictedSessionCryptoAdapter(BankingTokenIssuer tokens, TokenLookupHasher lookup,
                                          BankingTokenEnvelopeIssuer envelopes,
                                          LookupKeyVersion lookupVersion,
                                          LengthPrefixedSigningInputEncoder encoding,
                                          Sha256Digests digests) {
        this.tokens = Objects.requireNonNull(tokens);
        this.lookup = Objects.requireNonNull(lookup);
        this.envelopes = Objects.requireNonNull(envelopes);
        this.lookupVersion = Objects.requireNonNull(lookupVersion);
        this.encoding = Objects.requireNonNull(encoding);
        this.digests = Objects.requireNonNull(digests);
    }

    @Override
    public PreparedRestrictedSession prepare(RestrictedSession session, Instant expiresAt) {
        Objects.requireNonNull(session);
        Objects.requireNonNull(expiresAt);
        try {
            OpaqueBankingToken token = tokens.issue();
            Digest32 lookupDigest = lookup.digest(token.exactValue());
            String deviceKeyJkt = switch (session.target()) {
                case TrustTarget.KnownDevice known -> known.deviceKeyThumbprint().base64Url();
                case TrustTarget.NewDevice() -> null;
            };
            EncryptedBankingToken encrypted = envelopes.issue(token, ECKey.parse(session.keys().responsePublicJwk()),
                    new TokenDeliveryContext(session.operationId(), session.channel(),
                            BankingTokenStatus.NEED_TRUSTED_DEVICE,
                            session.keys().requestKeyThumbprint().base64Url(), deviceKeyJkt, expiresAt));
            return new PreparedRestrictedSession(session, UUID.randomUUID(),
                    new SessionTokenLookup(lookupVersion, lookupDigest),
                    deviceIdDigest(session.owner(), session.channel(), session.deviceId()),
                    expiresAt, encrypted.tokenEnvelope(), encrypted.receipt());
        } catch (ParseException failure) {
            throw new InvalidCryptographicInputException(failure);
        }
    }

    /**
     * Storage keeps only this digest of the App device ID. It is bound to the owner and channel,
     * so the same device ID does not correlate across customers.
     */
    @Override
    public Digest32 deviceIdDigest(SubjectId owner, String channel, String deviceId) {
        Objects.requireNonNull(owner);
        Objects.requireNonNull(channel);
        Objects.requireNonNull(deviceId);
        return digests.sha256(encoding.encode(List.of(DEVICE_ID_DIGEST_LABEL,
                owner.value().toString(), channel, deviceId)));
    }
}
