package com.vpbank.dcp.auth.application.port.in;

public sealed interface LogoutResult {
    /** The session is gone now (or was already gone): the app may discard the token. */
    record Ended() implements LogoutResult { }

    /** The store did not answer; the app must not assume the session ended. */
    record Unavailable() implements LogoutResult { }
}
