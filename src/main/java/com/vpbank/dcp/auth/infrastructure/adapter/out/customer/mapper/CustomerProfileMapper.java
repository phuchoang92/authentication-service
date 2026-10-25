package com.vpbank.dcp.auth.infrastructure.adapter.out.customer.mapper;

import com.vpbank.dcp.auth.application.port.out.model.CustomerProfile;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.infrastructure.adapter.out.customer.dto.CustomerProfileDto;

/** Customer wire body → the profile the registration flow reads. */
public final class CustomerProfileMapper {
    private static final String ELIGIBLE = "ELIGIBLE";

    private CustomerProfileMapper() {
    }

    public static CustomerProfile toProfile(CustomerId customerId, CustomerProfileDto body) {
        return CustomerProfile.builder()
                .customerId(customerId)
                .eligible(ELIGIBLE.equals(body.status()))
                .phone(body.phone())
                .phoneVerified(Boolean.TRUE.equals(body.phoneVerified()))
                .email(body.email())
                .emailVerified(Boolean.TRUE.equals(body.emailVerified()))
                .build();
    }
}
