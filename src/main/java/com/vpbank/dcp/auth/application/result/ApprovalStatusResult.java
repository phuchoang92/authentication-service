package com.vpbank.dcp.auth.application.result;

import com.vpbank.dcp.auth.domain.enums.EnrollmentState;
import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import java.time.Instant;

/** Where the requesting device's approval stands (slice 6). */
public sealed interface ApprovalStatusResult {
    record Status(EnrollmentId enrollmentId, EnrollmentState state, Instant expiresAt) implements ApprovalStatusResult { }

    /** This restricted session has not made an approval request. */
    record NoRequest() implements ApprovalStatusResult { }

    record SessionGone() implements ApprovalStatusResult { }

    record Unavailable() implements ApprovalStatusResult { }
}
