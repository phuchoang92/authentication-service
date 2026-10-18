package com.vpbank.dcp.infrastructure.adapter.out.redis.key;

import com.vpbank.dcp.core.domain.customer.SubjectId;
import java.util.Objects;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Keys of a session and of the per-channel list of a Customer's sessions (draft doc 21 §3).
 * The session ID comes from the token itself, so no lookup secret is needed.
 */
public final class SessionKeys {
    /** A channel is part of a key, so it may never contain the {@code :} separator. */
    private static final Pattern CHANNEL = Pattern.compile("[a-z0-9-]{1,32}");

    public String forSession(UUID sessionId) {
        Objects.requireNonNull(sessionId, "sessionId");
        return "session:v2:" + sessionId;
    }

    public String forNonceFamily(UUID sessionId) {
        Objects.requireNonNull(sessionId, "sessionId");
        return "nonce:v2:" + sessionId;
    }

    public String forSubjectSessions(String channel, SubjectId subject) {
        Objects.requireNonNull(channel, "channel");
        Objects.requireNonNull(subject, "subject");
        if (!CHANNEL.matcher(channel).matches()) {
            throw new IllegalArgumentException("channel is not a key-safe code");
        }
        return "subject-sessions:v1:" + channel + ":" + subject.value();
    }
}
