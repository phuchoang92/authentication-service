package com.vpbank.dcp.core.port.out.customer;

import java.util.UUID;

/** A durable owner decision, not permission to issue a banking token. */
public sealed interface CustomerOwnerAcceptance {

    record Accepted(UUID subjectId) implements CustomerOwnerAcceptance { }

    record Rejected() implements CustomerOwnerAcceptance { }

    record ReconciliationRequired() implements CustomerOwnerAcceptance { }

    record Conflict() implements CustomerOwnerAcceptance { }

    record NotClaimable() implements CustomerOwnerAcceptance { }
}
