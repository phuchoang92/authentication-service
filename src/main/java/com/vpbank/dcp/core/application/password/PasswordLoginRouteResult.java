package com.vpbank.dcp.core.application.password;

import java.util.UUID;

/** Device decision after a durable credential and Customer owner check; not a session. */
public sealed interface PasswordLoginRouteResult {

    record LastTrusted(UUID subjectId) implements PasswordLoginRouteResult { }

    record MfaUnavailable() implements PasswordLoginRouteResult { }

    record Rejected() implements PasswordLoginRouteResult { }

    record Processing() implements PasswordLoginRouteResult { }

    record Conflict() implements PasswordLoginRouteResult { }

    record AuthorityClosed() implements PasswordLoginRouteResult { }
}
