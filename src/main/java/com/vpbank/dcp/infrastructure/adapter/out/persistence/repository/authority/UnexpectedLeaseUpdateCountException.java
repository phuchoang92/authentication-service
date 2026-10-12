package com.vpbank.dcp.infrastructure.adapter.out.persistence.repository.authority;

final class UnexpectedLeaseUpdateCountException extends RuntimeException {

    UnexpectedLeaseUpdateCountException() {
        super("Authority lease update affected an unexpected number of rows");
    }
}
