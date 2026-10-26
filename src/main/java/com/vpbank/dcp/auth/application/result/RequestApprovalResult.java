package com.vpbank.dcp.auth.application.result;

import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import java.time.Instant;

/** Outcome of a new device's approval request (slice 6). */
public sealed interface RequestApprovalResult {
    /** The request waits for the primary device; a repeated request from the same session returns the same one. */
    record WaitingApproval(EnrollmentId enrollmentId, Instant expiresAt) implements RequestApprovalResult { }

    /** An unknown installation must send its public key and platform. */
    record DeviceKeyRequired() implements RequestApprovalResult { }

    /** The customer already has the maximum number of installations waiting on this channel. */
    record TooManyPending() implements RequestApprovalResult { }

    /** The session is not restricted, or another enrollment path is already in progress on it. */
    record Conflict() implements RequestApprovalResult { }

    record SessionGone() implements RequestApprovalResult { }

    record Unavailable() implements RequestApprovalResult { }
}
