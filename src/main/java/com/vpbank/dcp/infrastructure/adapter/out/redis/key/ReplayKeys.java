package com.vpbank.dcp.infrastructure.adapter.out.redis.key;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.RequestKeyThumbprint;
import java.util.Objects;

public final class ReplayKeys {

    private final AuthorityScope scope;

    public ReplayKeys(AuthorityScope scope) {
        this.scope = Objects.requireNonNull(scope, "scope");
    }

    public String forDpop(RequestKeyThumbprint requestKey, Digest32 proofIdDigest) {
        Objects.requireNonNull(requestKey, "requestKey");
        Objects.requireNonNull(proofIdDigest, "proofIdDigest");
        return "dpop:used:v1:" + scope.value() + ":"
                + requestKey.digest().base64Url() + ":" + proofIdDigest.base64Url();
    }

    public String forEnrollment(RequestKeyThumbprint requestKey, Digest32 proofIdDigest) {
        Objects.requireNonNull(requestKey, "requestKey");
        Objects.requireNonNull(proofIdDigest, "proofIdDigest");
        return "enrollment:used:v1:" + scope.value() + ":"
                + requestKey.digest().base64Url() + ":" + proofIdDigest.base64Url();
    }
}
