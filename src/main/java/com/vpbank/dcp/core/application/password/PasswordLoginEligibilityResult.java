package com.vpbank.dcp.core.application.password;

import java.util.UUID;

/** Device decision after a durable credential and Customer owner check; not a session. */
public sealed interface PasswordLoginEligibilityResult {

    record LastTrusted(UUID subjectId) implements PasswordLoginEligibilityResult { }

    record MfaUnavailable() implements PasswordLoginEligibilityResult { }

    record Rejected() implements PasswordLoginEligibilityResult { }

    record Processing() implements PasswordLoginEligibilityResult { }

    record Conflict() implements PasswordLoginEligibilityResult { }

    record AuthorityClosed() implements PasswordLoginEligibilityResult { }
}
