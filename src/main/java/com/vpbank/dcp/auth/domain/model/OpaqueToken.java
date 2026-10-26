package com.vpbank.dcp.auth.domain.model;

import com.vpbank.dcp.auth.domain.enums.Channel;
import java.util.Objects;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The banking token the app presents (slice 7): {@code s1:auth:session:<channel>:<sessionId>:<secret>}.
 * {@code s1} is the format version, the channel and session ID say where the session lives, and the
 * secret (32 random bytes as unpadded base64url) proves possession. Nothing in it is hidden: the store
 * holds the secret and compares it. The value itself is never logged.
 */
public record OpaqueToken(String value) {
    static final String PREFIX = "s1:auth:session:";
    private static final Pattern FORMAT = Pattern.compile(
            "s1:auth:session:(MOBILE|WEB):([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}):([A-Za-z0-9_-]{43})");

    public OpaqueToken {
        Objects.requireNonNull(value, "value");
        if (!FORMAT.matcher(value).matches()) {
            throw new IllegalArgumentException("Token has an invalid format");
        }
    }

    public static OpaqueToken of(Channel channel, SessionId sessionId, String secret) {
        Objects.requireNonNull(channel, "channel");
        Objects.requireNonNull(sessionId, "sessionId");
        Objects.requireNonNull(secret, "secret");
        return new OpaqueToken(PREFIX + channel.name() + ":" + sessionId.value() + ":" + secret);
    }

    public Channel channel() {
        return Channel.valueOf(parts().group(1));
    }

    public SessionId sessionId() {
        return new SessionId(UUID.fromString(parts().group(2)));
    }

    /** The random part; compared with the stored one, never logged. */
    public String secret() {
        return parts().group(3);
    }

    private Matcher parts() {
        Matcher matcher = FORMAT.matcher(value);
        matcher.matches();
        return matcher;
    }

    @Override
    public String toString() {
        return "OpaqueToken[" + PREFIX + channel() + ":" + sessionId().value() + ":redacted]";
    }
}
