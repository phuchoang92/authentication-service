package com.vpbank.dcp.infrastructure.adapter.out.crypto;

import com.nimbusds.jose.jwk.ECKey;
import com.vpbank.dcp.core.customer.SubjectId;
import com.vpbank.dcp.core.security.Digest32;
import com.vpbank.dcp.core.session.PreparedRestrictedSession;
import com.vpbank.dcp.core.session.RestrictedSession;
import com.vpbank.dcp.core.session.RestrictedSessionCryptography;
import com.vpbank.dcp.core.session.TrustTarget;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * Issues the restricted token exactly like an ACTIVE one: {@code <sessionId>.<secret>}, Kenc JWE
 * and signed receipt. Only the receipt status differs, so the App cannot mistake it for ACTIVE.
 */
public final class RestrictedSessionCryptoAdapter implements RestrictedSessionCryptography {
    private static final String DEVICE_ID_DIGEST_LABEL = "RESTRICTED_SESSION_DEVICE_ID_V1";

    private final BankingTokenIssuer tokens;
    private final BankingTokenEnvelopeIssuer envelopes;
    private final LengthPrefixedSigningInputEncoder encoding;
    private final Sha256Digests digests;

    public RestrictedSessionCryptoAdapter(BankingTokenIssuer tokens,
                                          BankingTokenEnvelopeIssuer envelopes,
                                          LengthPrefixedSigningInputEncoder encoding,
                                          Sha256Digests digests) {
        this.tokens = Objects.requireNonNull(tokens);
        this.envelopes = Objects.requireNonNull(envelopes);
        this.encoding = Objects.requireNonNull(encoding);
        this.digests = Objects.requireNonNull(digests);
    }

    @Override
    public PreparedRestrictedSession prepare(RestrictedSession session, String deviceId,
                                             Instant expiresAt) {
        Objects.requireNonNull(session);
        Objects.requireNonNull(deviceId);
        Objects.requireNonNull(expiresAt);
        try {
            UUID sessionId = UUID.randomUUID();
            BankingTokenIssuer.IssuedBankingToken token = tokens.issue(sessionId);
            String deviceKeyJkt = switch (session.device().target()) {
                case TrustTarget.KnownDevice known -> known.deviceKeyThumbprint().base64Url();
                case TrustTarget.NewDevice() -> null;
            };
            EncryptedBankingToken encrypted = envelopes.issue(token.token(), ECKey.parse(session.keys().responsePublicJwk()),
                    new TokenDeliveryContext(session.operationId(), session.device().channel(),
                            BankingTokenStatus.NEED_TRUSTED_DEVICE,
                            session.keys().requestKeyThumbprint().base64Url(), deviceKeyJkt, expiresAt));
            return new PreparedRestrictedSession(session, sessionId, token.secretDigest(),
                    deviceIdDigest(session.customer().owner(), session.device().channel(), deviceId),
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
