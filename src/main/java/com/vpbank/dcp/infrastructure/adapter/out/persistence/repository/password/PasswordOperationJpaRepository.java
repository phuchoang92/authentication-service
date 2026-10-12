package com.vpbank.dcp.infrastructure.adapter.out.persistence.repository.password;

import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.Repository;
import org.springframework.data.repository.query.Param;

/** Scalar projections only; exposes no entity or CRUD mutation operation. */
public interface PasswordOperationJpaRepository extends Repository<PasswordOperationEntity, UUID> {
    @Query("""
            select new com.vpbank.dcp.infrastructure.adapter.out.persistence.repository.password.PasswordOperationProgressView(o.state)
              from PasswordOperationEntity o
             where o.id = :operationId and o.kind = 'PASSWORD_LOGIN'
            """)
    Optional<PasswordOperationProgressView> progress(@Param("operationId") UUID operationId);

    @Query("""
            select new com.vpbank.dcp.infrastructure.adapter.out.persistence.repository.password.VerifiedPasswordIdentityView(o.verifiedIssuer, o.verifiedSubject)
              from PasswordOperationEntity o
             where o.id = :operationId and o.kind = 'PASSWORD_LOGIN'
               and o.state in ('VERIFIED', 'CONFIRMED', 'COMPLETED')
            """)
    Optional<VerifiedPasswordIdentityView> verifiedIdentity(@Param("operationId") UUID operationId);
}
