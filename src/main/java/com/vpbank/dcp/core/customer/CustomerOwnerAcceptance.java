package com.vpbank.dcp.core.customer;

import java.util.UUID;

/** A durable owner decision, not permission to issue a banking token. */
public sealed interface CustomerOwnerAcceptance {

    record Accepted(SubjectId subject) implements CustomerOwnerAcceptance { }

    record Rejected() implements CustomerOwnerAcceptance { }

    record ReconciliationRequired() implements CustomerOwnerAcceptance { }

    record Conflict() implements CustomerOwnerAcceptance { }

    record NotClaimable() implements CustomerOwnerAcceptance { }
}
