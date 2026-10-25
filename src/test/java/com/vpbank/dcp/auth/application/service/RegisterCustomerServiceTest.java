package com.vpbank.dcp.auth.application.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.vpbank.dcp.auth.application.port.in.RegisterCustomerCommand;
import com.vpbank.dcp.auth.application.port.in.RegisterCustomerResult;
import com.vpbank.dcp.auth.application.port.out.CustomerDirectoryPort;
import com.vpbank.dcp.auth.application.port.out.CustomerProfile;
import com.vpbank.dcp.auth.application.port.out.IdentityProviderPort;
import com.vpbank.dcp.auth.application.port.out.IdentityProviderPort.CreateUserResult;
import com.vpbank.dcp.auth.application.port.out.InitialPasswordSms;
import com.vpbank.dcp.auth.application.port.out.NewIdentityUser;
import com.vpbank.dcp.auth.application.port.out.PartnerUnavailableException;
import com.vpbank.dcp.auth.application.port.out.SmsSenderPort;
import com.vpbank.dcp.auth.domain.model.Registration;
import com.vpbank.dcp.auth.domain.model.RegistrationId;
import com.vpbank.dcp.auth.domain.model.RegistrationState;
import com.vpbank.dcp.auth.domain.model.RequestDigest;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.Email;
import com.vpbank.dcp.auth.domain.model.PhoneNumber;
import com.vpbank.dcp.auth.domain.model.UserName;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;

class RegisterCustomerServiceTest {
    private static final String ISSUER = "https://kc.test/realms/test";
    private static final RegistrationId REQUEST =
            new RegistrationId(UUID.fromString("22222222-2222-4222-8222-222222222222"));
    private static final CustomerId CUSTOMER = new CustomerId("90359");
    private static final UserName ALICE = new UserName("alice");
    private static final PhoneNumber PHONE = new PhoneNumber("+84901234567");

    private final InMemoryRegistrationRepository repository = new InMemoryRegistrationRepository();
    private final CustomerDirectoryPort customers = mock(CustomerDirectoryPort.class);
    private final IdentityProviderPort identities = mock(IdentityProviderPort.class);
    private final SmsSenderPort sms = mock(SmsSenderPort.class);
    private final RegisterCustomerService service = service(() -> REQUEST);
    private final RegisterCustomerCommand alice = command("Nguyen", null);

    @BeforeEach
    void partnersSayYes() {
        when(customers.profile(CUSTOMER)).thenReturn(Optional.of(profile(true, PHONE.value(), true, null, false)));
        when(identities.createDisabledUser(any())).thenReturn(new CreateUserResult.Created(ISSUER, "sub-1"));
        when(sms.sendInitialPassword(any())).thenReturn(true);
    }

    @Test
    void createsTheAccountInTheSafeOrder() {
        assertThat(service.register(alice)).isEqualTo(new RegisterCustomerResult.Ready(REQUEST, CUSTOMER, ALICE, true));

        InOrder order = inOrder(identities, sms);
        order.verify(identities).createDisabledUser(NewIdentityUser.builder().userName(ALICE)
                .firstName("Alice").lastName("Nguyen").emailVerified(false).build());
        order.verify(identities).setPassword(eq("sub-1"), anyString());
        order.verify(sms).sendInitialPassword(any());
        order.verify(identities).enable("sub-1");
        Registration ready = repository.only();
        assertThat(ready.state()).isEqualTo(RegistrationState.READY);
        assertThat(ready.version()).isEqualTo(3);
        assertThat(ready.identitySubject()).isEqualTo("sub-1");
        assertThat(repository.identityUserNames).containsExactly("alice");
    }

    @Test
    void theSmsCarriesTheSamePasswordThatWasSetAndTheRequestIdAsMessageId() {
        service.register(alice);

        var set = ArgumentCaptor.forClass(String.class);
        var sent = ArgumentCaptor.forClass(InitialPasswordSms.class);
        verify(identities).setPassword(eq("sub-1"), set.capture());
        verify(sms).sendInitialPassword(sent.capture());
        assertThat(sent.getValue().password()).isEqualTo(set.getValue()).hasSize(12);
        assertThat(sent.getValue().messageId()).isEqualTo(REQUEST);
        assertThat(sent.getValue().phone()).isEqualTo(PHONE);
    }

    @Test
    void aRetryAfterReadyReturnsTheSameRequestWithoutCallingAnyone() {
        service.register(alice);
        clearInvocations(customers, identities, sms);

        assertThat(service.register(alice)).isEqualTo(new RegisterCustomerResult.Ready(REQUEST, CUSTOMER, ALICE, false));
        verifyNoInteractions(customers, identities, sms);
    }

    @Test
    void theSameCustomerWithOtherDataIsAConflict() {
        service.register(alice);
        clearInvocations(customers, identities, sms);

        assertThat(service.register(command("Tran", null))).isInstanceOf(RegisterCustomerResult.IdentityConflict.class);
        verifyNoInteractions(identities, sms);
    }

    @Test
    void aRetryWhileAnEarlierAttemptIsUnfinishedNeverCallsOutside() {
        when(identities.createDisabledUser(any())).thenThrow(new PartnerUnavailableException("Keycloak"));
        assertThat(service.register(alice)).isInstanceOf(RegisterCustomerResult.Unavailable.class);
        assertThat(repository.only().state()).isEqualTo(RegistrationState.RESERVED);
        clearInvocations(customers, identities, sms);

        assertThat(service.register(alice)).isInstanceOf(RegisterCustomerResult.Unavailable.class);
        verifyNoInteractions(customers, identities, sms);
    }

    @Test
    void anIneligibleCustomerOrUnverifiedContactGetsProfileIncompleteAndNothingIsReserved() {
        assertProfileIncomplete(profile(false, PHONE.value(), true, null, false), alice);
        assertProfileIncomplete(profile(true, PHONE.value(), false, null, false), alice);
        assertProfileIncomplete(profile(true, "+84999999999", true, null, false), alice);
        RegisterCustomerCommand withEmail = command("Nguyen", "alice@example.com");
        assertProfileIncomplete(profile(true, PHONE.value(), true, "alice@example.com", false), withEmail);
        when(customers.profile(CUSTOMER)).thenReturn(Optional.empty());
        assertThat(service.register(alice)).isInstanceOf(RegisterCustomerResult.ProfileIncomplete.class);
        assertThat(repository.rows).isEmpty();
        verifyNoInteractions(identities, sms);
    }

    @Test
    void aVerifiedEmailIsPassedToKeycloakAsVerified() {
        when(customers.profile(CUSTOMER)).thenReturn(Optional.of(profile(true, PHONE.value(), true,
                "alice@example.com", true)));

        assertThat(service.register(command("Nguyen", "Alice@Example.com")))
                .isInstanceOf(RegisterCustomerResult.Ready.class);
        verify(identities).createDisabledUser(NewIdentityUser.builder().userName(ALICE).firstName("Alice")
                .lastName("Nguyen").email(new Email("Alice@Example.com")).emailVerified(true).build());
    }

    @Test
    void aUserNameTakenInKeycloakIsAConflictAndFreesTheSlot() {
        when(identities.createDisabledUser(any())).thenReturn(new CreateUserResult.UserNameTaken());

        assertThat(service.register(alice)).isInstanceOf(RegisterCustomerResult.IdentityConflict.class);
        assertThat(repository.only().state()).isEqualTo(RegistrationState.FAILED);
        verifyNoInteractions(sms);
    }

    @Test
    void anSmsThatIsNotAcceptedLeavesTheUserDisabled() {
        when(sms.sendInitialPassword(any())).thenReturn(false);

        assertThat(service.register(alice)).isInstanceOf(RegisterCustomerResult.Unavailable.class);
        assertThat(repository.only().state()).isEqualTo(RegistrationState.USER_CREATED);
        verify(identities, never()).enable(anyString());
    }

    @Test
    void anEnableFailureWritesNoIdentity() {
        doThrow(new PartnerUnavailableException("Keycloak")).when(identities).enable("sub-1");

        assertThat(service.register(alice)).isInstanceOf(RegisterCustomerResult.Unavailable.class);
        assertThat(repository.only().state()).isEqualTo(RegistrationState.SMS_ACCEPTED);
        assertThat(repository.identityUserNames).isEmpty();
    }

    @Test
    void aUserNameAlreadyLinkedToAnotherCustomerIsAConflict() {
        repository.identityUserNames.add("alice");

        assertThat(service.register(alice)).isInstanceOf(RegisterCustomerResult.IdentityConflict.class);
        assertThat(repository.only().state()).isEqualTo(RegistrationState.FAILED);
    }

    @Test
    void anOpenRequestOfAnotherCustomerForTheSameUserNameIsAConflict() {
        repository.reserve(Registration.reserve(RegistrationId.random(), new CustomerId("77777"),
                new UserName("ALICE"), new RequestDigest(new byte[32]), Instant.parse("2026-10-26T00:00:00Z")));

        assertThat(service.register(alice)).isInstanceOf(RegisterCustomerResult.IdentityConflict.class);
        verifyNoInteractions(identities, sms);
    }

    @Test
    void anEarlierFailedRequestDoesNotBlockANewOne() {
        when(identities.createDisabledUser(any()))
                .thenReturn(new CreateUserResult.UserNameTaken())
                .thenReturn(new CreateUserResult.Created(ISSUER, "sub-2"));
        assertThat(service.register(alice)).isInstanceOf(RegisterCustomerResult.IdentityConflict.class);

        RegisterCustomerService second = service(RegistrationId::random);
        assertThat(second.register(alice)).isInstanceOf(RegisterCustomerResult.Ready.class);
    }

    @Test
    void aDatabaseOutageIsUnavailable() {
        repository.unavailable = true;

        assertThat(service.register(alice)).isInstanceOf(RegisterCustomerResult.Unavailable.class);
        verifyNoInteractions(identities, sms);
    }

    private RegisterCustomerService service(java.util.function.Supplier<RegistrationId> ids) {
        return new RegisterCustomerService(repository, customers, identities, sms, new RequestDigester(new byte[32]),
                new InitialPasswordGenerator(new SecureRandom(), 12),
                Clock.fixed(Instant.parse("2026-10-25T03:00:00Z"), ZoneOffset.UTC), Duration.ofHours(24), ids);
    }

    private static RegisterCustomerCommand command(String lastName, String email) {
        return RegisterCustomerCommand.builder().customerId(CUSTOMER).userName(ALICE).firstName("Alice")
                .lastName(lastName).phoneNumber(PHONE).email(email == null ? null : new Email(email)).build();
    }

    private static CustomerProfile profile(boolean eligible, String phone, boolean phoneVerified,
                                           String email, boolean emailVerified) {
        return CustomerProfile.builder().customerId(CUSTOMER).eligible(eligible).phone(phone)
                .phoneVerified(phoneVerified).email(email).emailVerified(emailVerified).build();
    }

    private void assertProfileIncomplete(CustomerProfile profile, RegisterCustomerCommand command) {
        when(customers.profile(CUSTOMER)).thenReturn(Optional.of(profile));
        assertThat(service.register(command)).isInstanceOf(RegisterCustomerResult.ProfileIncomplete.class);
    }
}
