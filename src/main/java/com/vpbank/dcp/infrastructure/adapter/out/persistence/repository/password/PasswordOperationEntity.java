package com.vpbank.dcp.infrastructure.adapter.out.persistence.repository.password;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.util.UUID;
import org.hibernate.annotations.Immutable;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/** Read-only field mapping; native SQL owns every operation transition. */
@Entity
@Table(name = "auth_operation")
@Immutable
public class PasswordOperationEntity {
    @Id
    @JdbcTypeCode(SqlTypes.BINARY)
    @Column(name = "id", columnDefinition = "BINARY(16)", nullable = false, updatable = false)
    private UUID id;

    @Column(name = "kind", length = 40, nullable = false, updatable = false)
    private String kind;

    @Column(name = "state", length = 24, nullable = false, updatable = false)
    private String state;

    @Column(name = "verified_issuer", length = 255, updatable = false)
    private String verifiedIssuer;

    @Column(name = "verified_subject", length = 255, updatable = false)
    private String verifiedSubject;

    protected PasswordOperationEntity() { }
}
