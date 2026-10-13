package com.vpbank.dcp.core.application.password;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.vpbank.dcp.core.domain.customer.CustomerAuthenticationState;
import com.vpbank.dcp.core.domain.customer.CustomerStatus;
import com.vpbank.dcp.core.domain.customer.VerifiedProviderIdentity;
import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.RequestKeyThumbprint;
import com.vpbank.dcp.core.port.in.password.PasswordLoginCommand;
import com.vpbank.dcp.core.port.out.keycloak.DirectGrantPasswordVerifier;
import com.vpbank.dcp.core.port.out.keycloak.KeycloakVerificationUnavailableException;
import com.vpbank.dcp.core.port.out.keycloak.PasswordVerification;
import com.vpbank.dcp.core.port.out.keycloak.PasswordVerificationOutcome;
import com.vpbank.dcp.core.port.out.password.PasswordOperationContext;
import com.vpbank.dcp.core.port.out.password.PasswordWireProofs;
import com.vpbank.dcp.core.port.out.security.VerifiedDpopProof;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class VerifyPasswordIdentityServiceTest {
    private final DirectGrantPasswordVerifier passwords = mock(DirectGrantPasswordVerifier.class);
    private final ConfirmPasswordLoginOwnerService owners = mock(ConfirmPasswordLoginOwnerService.class);
    private final VerifyPasswordIdentityService service = new VerifyPasswordIdentityService(passwords, owners);

    @Test
    void signedIdentityIsResolvedToConfirmedCustomer() {
        PasswordLoginCommand command = command();
        VerifiedProviderIdentity identity = new VerifiedProviderIdentity(
                "https://keycloak.test/realms/bank", "subject-a");
        UUID customerId = UUID.randomUUID();
        CustomerAuthenticationState customer = new CustomerAuthenticationState("customer-a",
                CustomerStatus.ELIGIBLE, 3, 0, command.now());
        when(passwords.verify(command.credential()))
                .thenReturn(new PasswordVerificationOutcome.Verified(identity));
        when(owners.confirmOwner(identity, command.now()))
                .thenReturn(new PasswordLoginOwnerResult.Accepted(customerId, customer));

        assertThat(service.verify(command))
                .isEqualTo(new PasswordIdentityResult.Verified(customerId, customer));
        verify(passwords).verify(command.credential());
    }

    @Test
    void rejectedPasswordNeverQueriesCustomer() {
        PasswordLoginCommand command = command();
        when(passwords.verify(command.credential())).thenReturn(new PasswordVerificationOutcome.Rejected());

        assertThat(service.verify(command)).isInstanceOf(PasswordIdentityResult.Rejected.class);
        verify(owners, never()).confirmOwner(any(), any());
    }

    @Test
    void timeoutReturnsUnavailableWithoutRetryOrCustomerLookup() {
        PasswordLoginCommand command = command();
        when(passwords.verify(command.credential())).thenThrow(new KeycloakVerificationUnavailableException());

        assertThat(service.verify(command)).isInstanceOf(PasswordIdentityResult.Unavailable.class);
        verify(passwords).verify(eq(command.credential()));
        verify(owners, never()).confirmOwner(any(), any());
    }

    private PasswordLoginCommand command() {
        Instant now = Instant.parse("2026-10-13T00:00:00Z");
        Digest32 digest = Digest32.fromBytes(new byte[32]);
        VerifiedDpopProof dpop = new VerifiedDpopProof(new RequestKeyThumbprint(digest),
                digest, now, "public-jwk");
        return new PasswordLoginCommand(new PasswordOperationContext(UUID.randomUUID(),
                "neo-mobile", "ANDROID", "installation-1234567890", "alice", null),
                new PasswordVerification("alice", "secret"),
                new PasswordWireProofs(dpop, "request-proof", null, "recipient-key"),
                now, now.plusSeconds(8), now.plusSeconds(900));
    }
}
