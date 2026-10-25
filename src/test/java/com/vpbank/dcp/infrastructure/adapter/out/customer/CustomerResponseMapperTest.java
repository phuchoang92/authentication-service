package com.vpbank.dcp.infrastructure.adapter.out.customer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.vpbank.dcp.core.customer.CustomerStatus;
import com.vpbank.dcp.core.customer.CustomerDirectoryUnavailableException;
import org.junit.jupiter.api.Test;

class CustomerResponseMapperTest {

    @Test
    void mapsOnlyKnownWireStatusCodes() {
        assertEquals(CustomerStatus.ELIGIBLE,
                CustomerResponseMapper.fromResolve(response("ELIGIBLE")).status());
        assertEquals(CustomerStatus.BLOCKED,
                CustomerResponseMapper.fromResolve(new CustomerResponse("CUST-001", "BLOCKED",
                        43L, 43L, "2026-10-11T03:10:00Z")).status());
        assertThrows(CustomerDirectoryUnavailableException.class,
                () -> CustomerResponseMapper.fromResolve(response("SUSPENDED")));
        assertThrows(CustomerDirectoryUnavailableException.class,
                () -> CustomerResponseMapper.fromResolve(response("eligible")));
    }

    @Test
    void rejectsMissingOrInvalidProviderData() {
        assertThrows(CustomerDirectoryUnavailableException.class,
                () -> CustomerResponseMapper.fromResolve(null));
        assertThrows(CustomerDirectoryUnavailableException.class,
                () -> CustomerResponseMapper.fromResolve(new CustomerResponse("CUST-001",
                        "ELIGIBLE", null, 42L, "2026-10-11T03:10:00Z")));
        assertThrows(CustomerDirectoryUnavailableException.class,
                () -> CustomerResponseMapper.fromResolve(new CustomerResponse("CUST-001",
                        "ELIGIBLE", 43L, 42L, "2026-10-11T03:10:00+00:00")));
        assertThrows(CustomerDirectoryUnavailableException.class,
                () -> CustomerResponseMapper.fromResolve(new CustomerResponse("CUST-001",
                        "ELIGIBLE", 43L, 42L, "not-a-dateZ")));
        assertThrows(CustomerDirectoryUnavailableException.class,
                () -> CustomerResponseMapper.fromResolve(new CustomerResponse("CUST-001",
                        "ELIGIBLE", -1L, 0L, "2026-10-11T03:10:00Z")));
    }

    @Test
    void statusReadMustBelongToRequestedCustomer() {
        assertThrows(CustomerDirectoryUnavailableException.class,
                () -> CustomerResponseMapper.fromStatus("CUST-OTHER", response("ELIGIBLE")));
    }

    private CustomerResponse response(String status) {
        return new CustomerResponse("CUST-001", status, 43L, 42L,
                "2026-10-11T03:10:00Z");
    }
}
