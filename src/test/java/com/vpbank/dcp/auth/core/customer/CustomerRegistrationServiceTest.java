package com.vpbank.dcp.auth.core.customer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.vpbank.dcp.auth.core.customer.IdentityProvider.CreateUserResult;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;

class CustomerRegistrationServiceTest {
    private static final String ISSUER = "https://kc.test/realms/test";
    private static final UUID REQUEST = UUID.fromString("22222222-2222-4222-8222-222222222222");

    private final InMemoryRegistrationStore store = new InMemoryRegistrationStore();
    private final CustomerDirectory customers = mock(CustomerDirectory.class);
    private final IdentityProvider identities = mock(IdentityProvider.class);
    private final SmsSender sms = mock(SmsSender.class);
    private final CustomerRegistrationService service = new CustomerRegistrationService(store, customers,
            identities, sms, new RequestDigester(new byte[32]),
            new InitialPasswordGenerator(new SecureRandom(), 12),
            Clock.fixed(Instant.parse("2026-10-25T03:00:00Z"), ZoneOffset.UTC), Duration.ofHours(24),
            () -> REQUEST);
    private final RegistrationCommand alice = new RegistrationCommand("90359", "alice", "Alice", "Nguyen",
            "+84901234567", null);

    @BeforeEach
    void partnersSayYes() {
        when(customers.profile("90359")).thenReturn(Optional.of(
                new CustomerProfile("90359", true, "+84901234567", true, null, false)));
        when(identities.createDisabledUser(anyString(), anyString(), anyString(), any(), anyBoolean()))
                .thenReturn(new CreateUserResult.Created(ISSUER, "sub-1"));
        when(sms.sendInitialPassword(any(), anyString(), anyString(), anyString(), anyString())).thenReturn(true);
    }

    @Test
    void createsTheAccountInTheSafeOrder() {
        assertThat(service.register(alice))
                .isEqualTo(new RegistrationResult.Ready(REQUEST, "90359", "alice", true));

        InOrder order = inOrder(identities, sms);
        order.verify(identities).createDisabledUser("alice", "Alice", "Nguyen", null, false);
        order.verify(identities).setPassword(eq("sub-1"), anyString());
        order.verify(sms).sendInitialPassword(eq(REQUEST), eq("90359"), eq("+84901234567"), eq("alice"),
                anyString());
        order.verify(identities).enable("sub-1");
        Registration ready = store.only();
        assertThat(ready.state()).isEqualTo(RegistrationState.READY);
        assertThat(ready.identitySubject()).isEqualTo("sub-1");
        assertThat(store.identityUserNames).containsExactly("alice");
    }

    @Test
    void theSmsCarriesTheSamePasswordThatWasSet() {
        service.register(alice);

        var set = org.mockito.ArgumentCaptor.forClass(String.class);
        var sent = org.mockito.ArgumentCaptor.forClass(String.class);
        verify(identities).setPassword(eq("sub-1"), set.capture());
        verify(sms).sendInitialPassword(any(), anyString(), anyString(), anyString(), sent.capture());
        assertThat(sent.getValue()).isEqualTo(set.getValue()).hasSize(12);
    }

    @Test
    void aRetryAfterReadyReturnsTheSameRequestWithoutCallingAnyone() {
        service.register(alice);
        org.mockito.Mockito.clearInvocations(customers, identities, sms);

        assertThat(service.register(alice))
                .isEqualTo(new RegistrationResult.Ready(REQUEST, "90359", "alice", false));
        verifyNoInteractions(customers, identities, sms);
    }

    @Test
    void theSameCustomerWithOtherDataIsAConflict() {
        service.register(alice);
        org.mockito.Mockito.clearInvocations(customers, identities, sms);

        RegistrationCommand other = new RegistrationCommand("90359", "alice", "Alice", "Tran",
                "+84901234567", null);
        assertThat(service.register(other)).isInstanceOf(RegistrationResult.IdentityConflict.class);
        verifyNoInteractions(identities, sms);
    }

    @Test
    void aRetryWhileAnEarlierAttemptIsUnfinishedNeverCallsOutside() {
        when(identities.createDisabledUser(anyString(), anyString(), anyString(), any(), anyBoolean()))
                .thenThrow(new PartnerUnavailableException("Keycloak"));
        assertThat(service.register(alice)).isInstanceOf(RegistrationResult.Unavailable.class);
        assertThat(store.only().state()).isEqualTo(RegistrationState.RESERVED);
        org.mockito.Mockito.clearInvocations(customers, identities, sms);

        assertThat(service.register(alice)).isInstanceOf(RegistrationResult.Unavailable.class);
        verifyNoInteractions(customers, identities, sms);
    }

    @Test
    void anIneligibleCustomerOrUnverifiedContactGetsProfileIncompleteAndNothingIsReserved() {
        assertProfileIncomplete(new CustomerProfile("90359", false, "+84901234567", true, null, false), alice);
        assertProfileIncomplete(new CustomerProfile("90359", true, "+84901234567", false, null, false), alice);
        assertProfileIncomplete(new CustomerProfile("90359", true, "+84999999999", true, null, false), alice);
        RegistrationCommand withEmail = new RegistrationCommand("90359", "alice", "Alice", "Nguyen",
                "+84901234567", "alice@example.com");
        assertProfileIncomplete(new CustomerProfile("90359", true, "+84901234567", true,
                "alice@example.com", false), withEmail);
        when(customers.profile("90359")).thenReturn(Optional.empty());
        assertThat(service.register(alice)).isInstanceOf(RegistrationResult.ProfileIncomplete.class);
        assertThat(store.rows).isEmpty();
        verifyNoInteractions(identities, sms);
    }

    @Test
    void aVerifiedEmailIsPassedToKeycloakAsVerified() {
        RegistrationCommand withEmail = new RegistrationCommand("90359", "alice", "Alice", "Nguyen",
                "+84901234567", "Alice@Example.com");
        when(customers.profile("90359")).thenReturn(Optional.of(new CustomerProfile("90359", true,
                "+84901234567", true, "alice@example.com", true)));

        assertThat(service.register(withEmail)).isInstanceOf(RegistrationResult.Ready.class);
        verify(identities).createDisabledUser("alice", "Alice", "Nguyen", "Alice@Example.com", true);
    }

    @Test
    void aUserNameTakenInKeycloakIsAConflictAndFreesTheSlot() {
        when(identities.createDisabledUser(anyString(), anyString(), anyString(), any(), anyBoolean()))
                .thenReturn(new CreateUserResult.UserNameTaken());

        assertThat(service.register(alice)).isInstanceOf(RegistrationResult.IdentityConflict.class);
        assertThat(store.only().state()).isEqualTo(RegistrationState.FAILED);
        verifyNoInteractions(sms);
    }

    @Test
    void anSmsThatIsNotAcceptedLeavesTheUserDisabled() {
        when(sms.sendInitialPassword(any(), anyString(), anyString(), anyString(), anyString())).thenReturn(false);

        assertThat(service.register(alice)).isInstanceOf(RegistrationResult.Unavailable.class);
        assertThat(store.only().state()).isEqualTo(RegistrationState.USER_CREATED);
        verify(identities, never()).enable(anyString());
    }

    @Test
    void anEnableFailureWritesNoIdentity() {
        doThrow(new PartnerUnavailableException("Keycloak")).when(identities).enable("sub-1");

        assertThat(service.register(alice)).isInstanceOf(RegistrationResult.Unavailable.class);
        assertThat(store.only().state()).isEqualTo(RegistrationState.SMS_ACCEPTED);
        assertThat(store.identityUserNames).isEmpty();
    }

    @Test
    void aUserNameAlreadyLinkedToAnotherCustomerIsAConflict() {
        store.identityUserNames.add("alice");

        assertThat(service.register(alice)).isInstanceOf(RegistrationResult.IdentityConflict.class);
        assertThat(store.only().state()).isEqualTo(RegistrationState.FAILED);
    }

    @Test
    void anOpenRequestOfAnotherCustomerForTheSameUserNameIsAConflict() {
        store.reserve(UUID.randomUUID(), "77777", "ALICE", new RequestDigest(new byte[32]),
                Instant.parse("2026-10-26T00:00:00Z"), Instant.parse("2026-10-25T00:00:00Z"));

        assertThat(service.register(alice)).isInstanceOf(RegistrationResult.IdentityConflict.class);
        verifyNoInteractions(identities, sms);
    }

    @Test
    void anEarlierFailedRequestDoesNotBlockANewOne() {
        when(identities.createDisabledUser(anyString(), anyString(), anyString(), isNull(), anyBoolean()))
                .thenReturn(new CreateUserResult.UserNameTaken())
                .thenReturn(new CreateUserResult.Created(ISSUER, "sub-2"));
        assertThat(service.register(alice)).isInstanceOf(RegistrationResult.IdentityConflict.class);

        CustomerRegistrationService second = new CustomerRegistrationService(store, customers, identities, sms,
                new RequestDigester(new byte[32]), new InitialPasswordGenerator(new SecureRandom(), 12),
                Clock.systemUTC(), Duration.ofHours(24), () -> UUID.fromString("33333333-3333-4333-8333-333333333333"));
        assertThat(second.register(alice)).isInstanceOf(RegistrationResult.Ready.class);
    }

    @Test
    void aDatabaseOutageIsUnavailable() {
        store.unavailable = true;

        assertThat(service.register(alice)).isInstanceOf(RegistrationResult.Unavailable.class);
        verifyNoInteractions(identities, sms);
    }

    private void assertProfileIncomplete(CustomerProfile profile, RegistrationCommand command) {
        when(customers.profile("90359")).thenReturn(Optional.of(profile));
        assertThat(service.register(command)).isInstanceOf(RegistrationResult.ProfileIncomplete.class);
    }
}
