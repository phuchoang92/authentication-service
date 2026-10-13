package com.vpbank.dcp.infrastructure.adapter.out.redis.key;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.RequestKeyThumbprint;
import java.util.Objects;
import java.util.UUID;

/** Typed authority keys; no raw proof IDs, credentials or App identifiers appear in Redis keys. */
public final class PasswordProofReplayKeys {

    private final AuthorityScope scope;

    public PasswordProofReplayKeys(AuthorityScope scope) {
        this.scope = Objects.requireNonNull(scope, "scope");
    }

    public String forOperation(UUID operationId) {
        Objects.requireNonNull(operationId, "operationId");
        return "password:operation:used:v1:" + scope.value() + ":" + operationId;
    }

    public String forRequestKey(RequestKeyThumbprint key, Digest32 proofIdDigest) {
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(proofIdDigest, "proofIdDigest");
        return "password:request:used:v1:" + scope.value() + ":"
                + key.digest().base64Url() + ":" + proofIdDigest.base64Url();
    }

    public String forDeviceKey(Digest32 keyThumbprint, Digest32 proofIdDigest) {
        Objects.requireNonNull(keyThumbprint, "keyThumbprint");
        Objects.requireNonNull(proofIdDigest, "proofIdDigest");
        return "password:device:used:v1:" + scope.value() + ":"
                + keyThumbprint.base64Url() + ":" + proofIdDigest.base64Url();
    }
}
