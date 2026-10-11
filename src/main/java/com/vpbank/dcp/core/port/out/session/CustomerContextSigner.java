package com.vpbank.dcp.core.port.out.session;

import java.time.Instant;
import java.util.UUID;

/** Signs a narrow workload-to-domain context after online admission, never before. */
public interface CustomerContextSigner {
    String sign(UUID subjectId, UUID bindingId, String appId, String audience,
                String action, Instant expiresAt);
}
