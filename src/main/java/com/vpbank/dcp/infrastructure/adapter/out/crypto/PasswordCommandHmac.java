package com.vpbank.dcp.infrastructure.adapter.out.crypto;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.port.out.password.PasswordCommandHasher;
import com.vpbank.dcp.core.port.out.password.PasswordSemanticCommand;
import com.vpbank.dcp.core.port.out.password.PasswordReservationFingerprints;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** HMAC-SHA-256 of LP-encoded semantic fields, including the exact password bytes. */
public final class PasswordCommandHmac implements PasswordCommandHasher {

    private final String activeKeyId;
    private final Map<String, byte[]> keys;
    private final LengthPrefixedSigningInputEncoder lengthPrefixEncoder;
    private final Sha256Digests digests = new Sha256Digests();

    public PasswordCommandHmac(String activeKeyId, Map<String, byte[]> keys,
                               LengthPrefixedSigningInputEncoder lengthPrefixEncoder) {
        this.activeKeyId = Objects.requireNonNull(activeKeyId, "activeKeyId");
        Objects.requireNonNull(keys, "keys");
        this.lengthPrefixEncoder = Objects.requireNonNull(lengthPrefixEncoder,
                "lengthPrefixEncoder");
        Map<String, byte[]> copied = new HashMap<>();
        keys.forEach((id, key) -> {
            if (id == null || !id.matches("[A-Za-z0-9_-]{1,16}")
                    || key == null || key.length < 32) {
                throw new InvalidPasswordHmacKeyException();
            }
            copied.put(id, key.clone());
        });
        if (!copied.containsKey(activeKeyId)) {
            throw new InvalidPasswordHmacKeyException();
        }
        this.keys = Map.copyOf(copied);
    }

    @Override
    public String activeKeyId() {
        return activeKeyId;
    }

    @Override
    public Digest32 digest(PasswordSemanticCommand command, String keyId) {
        Objects.requireNonNull(command, "command");
        byte[] key = keys.get(keyId);
        if (key == null) {
            throw new InvalidPasswordHmacKeyException();
        }
        byte[] encoded = lengthPrefixEncoder.encode(fields(command));
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return Digest32.fromBytes(mac.doFinal(encoded));
        } catch (GeneralSecurityException failure) {
            throw new CryptographicProviderUnavailableException(failure);
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
    }

    @Override
    public PasswordReservationFingerprints prepare(PasswordSemanticCommand command) {
        Objects.requireNonNull(command, "command");
        var operation = command.operation();
        byte[] scopeInput = lengthPrefixEncoder.encode(List.of("PASSWORD_OWNER_SCOPE_V1",
                operation.appId(), command.proofs().requestKey().digest().base64Url()));
        try {
            return new PasswordReservationFingerprints(digests.sha256(scopeInput),
                    digests.sha256(operation.operationId().toString().getBytes(StandardCharsets.UTF_8)),
                    digest(command, activeKeyId), activeKeyId,
                    digests.sha256(operation.installationId().getBytes(StandardCharsets.UTF_8)));
        } finally {
            Arrays.fill(scopeInput, (byte) 0);
        }
    }

    private List<String> fields(PasswordSemanticCommand command) {
        var operation = command.operation();
        var proofs = command.proofs();
        return List.of("PASSWORD_LOGIN_COMMAND_V1", operation.operationId().toString(),
                operation.appId(), operation.platform(), operation.installationId(),
                operation.username(), command.credential().password(),
                operation.claimedBindingId() == null ? "" : operation.claimedBindingId().toString(),
                proofs.requestKey().digest().base64Url(),
                proofs.deviceKeyThumbprint() == null ? ""
                        : proofs.deviceKeyThumbprint().base64Url(),
                proofs.responseKeyThumbprint().base64Url());
    }

    @Override
    public String toString() { return "PasswordCommandHmac[redacted]"; }
}
