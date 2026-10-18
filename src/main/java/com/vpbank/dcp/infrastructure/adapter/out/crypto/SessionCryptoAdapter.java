package com.vpbank.dcp.infrastructure.adapter.out.crypto;

import com.nimbusds.jose.jwk.ECKey;
import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.session.SessionDeadlines;
import com.vpbank.dcp.core.port.out.session.SessionCryptography;
import com.vpbank.dcp.core.port.out.session.SessionActivationSnapshot;
import com.vpbank.dcp.core.port.out.session.SessionActivationContext;
import com.vpbank.dcp.core.port.out.session.SessionKeyBindings;
import com.vpbank.dcp.core.port.out.session.PreparedSession;
import com.vpbank.dcp.core.port.out.session.SessionDelivery;
import com.vpbank.dcp.core.port.out.session.SessionCandidate;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.text.ParseException;
import java.time.Instant;
import java.util.List;
import java.util.Base64;
import java.util.Objects;
import java.util.UUID;

/** Generates one candidate; a failed SQL reservation discards it without exposing a token. */
public final class SessionCryptoAdapter implements SessionCryptography {
    private final BankingTokenIssuer tokens;
    private final BankingTokenEnvelopeIssuer envelopes;
    private final LengthPrefixedSigningInputEncoder encoding;
    private final Sha256Digests digests;
    private final SecureRandom random;

    public SessionCryptoAdapter(BankingTokenIssuer tokens, BankingTokenEnvelopeIssuer envelopes,
                                LengthPrefixedSigningInputEncoder encoding, Sha256Digests digests,
                                SecureRandom random) {
        this.tokens = Objects.requireNonNull(tokens);
        this.envelopes = Objects.requireNonNull(envelopes);
        this.encoding = Objects.requireNonNull(encoding);
        this.digests = Objects.requireNonNull(digests);
        this.random = Objects.requireNonNull(random);
    }

    @Override
    public PreparedSession prepare(SessionActivationSnapshot snapshot, UUID generation,
                                           SessionDeadlines deadlines, Instant deliveryDeadline) {
        SessionActivationContext context = snapshot.context();
        SessionKeyBindings keys = snapshot.keys();
        try {
            UUID intentId = UUID.randomUUID();
            UUID sessionId = UUID.randomUUID();
            BankingTokenIssuer.IssuedBankingToken token = tokens.issue(sessionId);
            byte[] nonceBytes = new byte[32];
            random.nextBytes(nonceBytes);
            String dpopNonce = Base64.getUrlEncoder().withoutPadding().encodeToString(nonceBytes);
            EncryptedBankingToken encrypted = envelopes.issue(token.token(),
                    ECKey.parse(keys.responsePublicJwk()),
                    new TokenDeliveryContext(context.operationId(), context.appId(),
                            BankingTokenStatus.ACTIVE, keys.requestKey().base64Url(),
                            keys.deviceKey().base64Url(), deadlines.absoluteExpiresAt()));
            Digest32 envelopeDigest = digests.sha256(
                    encrypted.tokenEnvelope().getBytes(StandardCharsets.US_ASCII));
            byte[] candidateBytes = encoding.encode(List.of("PASSWORD_ACTIVE_V2",
                    context.operationId().toString(), intentId.toString(), sessionId.toString(),
                    generation.toString(), token.secretDigest().base64Url(),
                    context.subject().value().toString(), context.bindingId().value().toString(),
                    keys.requestKey().base64Url(),
                    Long.toString(deadlines.idleExpiresAt().toEpochMilli()),
                    Long.toString(deadlines.absoluteExpiresAt().toEpochMilli()),
                    envelopeDigest.base64Url(), dpopNonce));
            Digest32 candidateDigest = digests.sha256(candidateBytes);
            var candidate = new SessionCandidate(intentId, sessionId, generation,
                    token.secretDigest(), candidateDigest);
            var delivery = new SessionDelivery(encrypted.tokenEnvelope(), encrypted.receipt(),
                    dpopNonce, deliveryDeadline);
            return new PreparedSession(snapshot, candidate, delivery, deadlines);
        } catch (ParseException failure) {
            throw new InvalidCryptographicInputException(failure);
        }
    }
}
