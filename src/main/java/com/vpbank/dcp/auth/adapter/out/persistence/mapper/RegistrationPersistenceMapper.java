package com.vpbank.dcp.auth.adapter.out.persistence.mapper;

import com.vpbank.dcp.auth.adapter.out.persistence.entity.CustomerAuthenticationEntity;
import com.vpbank.dcp.auth.adapter.out.persistence.entity.RegistrationEntity;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.Registration;
import com.vpbank.dcp.auth.domain.model.RegistrationId;
import com.vpbank.dcp.auth.domain.model.RequestDigest;
import com.vpbank.dcp.auth.domain.model.UserName;

/** Registration aggregate ↔ phase-1 rows. Value objects are built on the way out of the database. */
public final class RegistrationPersistenceMapper {
    private RegistrationPersistenceMapper() {
    }

    public static RegistrationEntity toEntity(Registration registration) {
        return RegistrationEntity.builder()
                .requestId(registration.id().value())
                .customerId(registration.customerId().value())
                .userName(registration.userName().value())
                .requestDigest(registration.requestDigest().bytes())
                .state(registration.state())
                .identityIssuer(registration.identityIssuer())
                .identitySubject(registration.identitySubject())
                .expiresAt(registration.expiresAt())
                .version(registration.version())
                .build();
    }

    public static Registration toDomain(RegistrationEntity entity) {
        return Registration.builder()
                .id(new RegistrationId(entity.getRequestId()))
                .customerId(new CustomerId(entity.getCustomerId()))
                .userName(new UserName(entity.getUserName()))
                .requestDigest(new RequestDigest(entity.getRequestDigest()))
                .state(entity.getState())
                .identityIssuer(entity.getIdentityIssuer())
                .identitySubject(entity.getIdentitySubject())
                .expiresAt(entity.getExpiresAt())
                .version(entity.getVersion())
                .build();
    }

    /** Copies the step the aggregate decided onto the managed row. */
    public static void apply(RegistrationEntity entity, Registration changed) {
        entity.applyStep(changed.state(), changed.identityIssuer(), changed.identitySubject());
    }

    /** The identity row written when a registration completes. */
    public static CustomerAuthenticationEntity toIdentity(Registration completed) {
        return CustomerAuthenticationEntity.builder()
                .customerId(completed.customerId().value())
                .userName(completed.userName().value())
                .identityIssuer(completed.identityIssuer())
                .identitySubject(completed.identitySubject())
                .status(CustomerAuthenticationEntity.STATUS_ACTIVE)
                .build();
    }
}
