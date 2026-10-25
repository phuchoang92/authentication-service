package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.port.in.RegisterCustomerCommand;
import com.vpbank.dcp.auth.application.port.in.RegisterCustomerResult;
import com.vpbank.dcp.auth.application.port.in.RegisterCustomerUseCase;
import com.vpbank.dcp.auth.application.port.out.CustomerDirectoryPort;
import com.vpbank.dcp.auth.application.port.out.CustomerProfile;
import com.vpbank.dcp.auth.application.port.out.IdentityProviderPort;
import com.vpbank.dcp.auth.application.port.out.IdentityProviderPort.CreateUserResult;
import com.vpbank.dcp.auth.application.port.out.InitialPasswordSms;
import com.vpbank.dcp.auth.application.port.out.NewIdentityUser;
import com.vpbank.dcp.auth.application.port.out.PartnerUnavailableException;
import com.vpbank.dcp.auth.application.port.out.RegistrationRepository;
import com.vpbank.dcp.auth.application.port.out.RegistrationRepository.ReserveResult;
import com.vpbank.dcp.auth.application.port.out.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.port.out.SmsSenderPort;
import com.vpbank.dcp.auth.domain.model.Registration;
import com.vpbank.dcp.auth.domain.model.RegistrationId;
import com.vpbank.dcp.auth.domain.model.RegistrationState;
import com.vpbank.dcp.auth.domain.model.RequestDigest;

import lombok.NonNull;
import lombok.RequiredArgsConstructor;

import java.time.Clock;
import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * Creates the login account of a customer who finished onboarding (contract §1):
 * reserve → check Customer → create the Keycloak user disabled → set its password →
 * SMS accepted → enable → write the identity and READY.
 *
 * <p>The order is a security rule: nobody can log in before Notification accepted the SMS, and
 * the identity row exists only once the account is usable. Each step is saved before the next
 * one starts. If a step fails or its outcome is unknown, the request stays where it is and a
 * retry returns UNAVAILABLE: it never calls Keycloak or Notification again blindly.
 *
 * <p>{@code requestLifetime} arrives validated (positive) from configuration.
 */
@RequiredArgsConstructor
public final class RegisterCustomerService implements RegisterCustomerUseCase {
    @NonNull private final RegistrationRepository registrations;
    @NonNull private final CustomerDirectoryPort customers;
    @NonNull private final IdentityProviderPort identities;
    @NonNull private final SmsSenderPort sms;
    @NonNull private final RequestDigester digester;
    @NonNull private final InitialPasswordGenerator passwords;
    @NonNull private final Clock clock;
    @NonNull private final Duration requestLifetime;
    @NonNull private final Supplier<RegistrationId> requestIds;

    @Override
    public RegisterCustomerResult register(RegisterCustomerCommand command) {
        Objects.requireNonNull(command, "command");
        RequestDigest digest = digester.digest(command);
        try {
            Optional<RegisterCustomerResult> earlier = registrations.findLatest(command.customerId())
                    .flatMap(previous -> answerForEarlier(previous, digest));
            if (earlier.isPresent()) {
                return earlier.get();
            }
            if (!profileMatches(command)) {
                return new RegisterCustomerResult.ProfileIncomplete();
            }
            Registration fresh = Registration.reserve(requestIds.get(), command.customerId(),
                    command.userName(), digest, clock.instant().plus(requestLifetime));
            return switch (registrations.reserve(fresh)) {
                case ReserveResult.Reserved(var reserved) -> createAccount(command, reserved);
                case ReserveResult.CustomerHasOpen(var existing) ->
                        answerForEarlier(existing, digest).orElseGet(RegisterCustomerResult.Unavailable::new);
                case ReserveResult.UserNameTaken() -> new RegisterCustomerResult.IdentityConflict();
            };
        } catch (RepositoryUnavailableException | PartnerUnavailableException failure) {
            return new RegisterCustomerResult.Unavailable();
        }
    }

    /**
     * A retry or a second call for a customer who already has a request. Empty when the earlier
     * request FAILED, so a new one may start.
     */
    private static Optional<RegisterCustomerResult> answerForEarlier(Registration earlier, RequestDigest digest) {
        if (earlier.state() == RegistrationState.FAILED) {
            return Optional.empty();
        }
        if (!earlier.isSameRequest(digest)) {
            return Optional.of(new RegisterCustomerResult.IdentityConflict());
        }
        if (earlier.state() == RegistrationState.READY) {
            return Optional.of(new RegisterCustomerResult.Ready(earlier.id(), earlier.customerId(),
                    earlier.userName(), false));
        }
        // Same data, still open: an earlier attempt is in progress or its outcome is unknown.
        return Optional.of(new RegisterCustomerResult.Unavailable());
    }

    /** ELIGIBLE, and the phone (and email, when sent) is the one the Customer service verified. */
    private boolean profileMatches(RegisterCustomerCommand command) {
        Optional<CustomerProfile> found = customers.profile(command.customerId());
        if (found.isEmpty()) {
            return false;
        }
        CustomerProfile profile = found.get();
        boolean emailOk = command.email() == null
                || (profile.emailVerified() && command.email().sameAs(profile.email()));
        return profile.eligible() && profile.phoneVerified()
                && command.phoneNumber().value().equals(profile.phone()) && emailOk;
    }

    private RegisterCustomerResult createAccount(RegisterCustomerCommand command, Registration reserved) {
        CreateUserResult created = identities.createDisabledUser(NewIdentityUser.builder()
                .userName(command.userName()).firstName(command.firstName()).lastName(command.lastName())
                .email(command.email()).emailVerified(command.email() != null).build());
        if (created instanceof CreateUserResult.UserNameTaken) {
            registrations.save(reserved.fail());
            return new RegisterCustomerResult.IdentityConflict();
        }
        var user = (CreateUserResult.Created) created;
        Optional<Registration> userCreated = registrations.save(
                reserved.markUserCreated(user.identityIssuer(), user.identitySubject()));
        if (userCreated.isEmpty()) {
            return new RegisterCustomerResult.Unavailable();
        }

        String password = passwords.next();
        identities.setPassword(user.identitySubject(), password);
        boolean accepted = sms.sendInitialPassword(InitialPasswordSms.builder()
                .messageId(reserved.id()).customerId(command.customerId()).phone(command.phoneNumber())
                .userName(command.userName()).password(password).build());
        Optional<Registration> smsAccepted = accepted
                ? registrations.save(userCreated.get().markSmsAccepted()) : Optional.empty();
        if (smsAccepted.isEmpty()) {
            return new RegisterCustomerResult.Unavailable();
        }

        identities.enable(user.identitySubject());
        Registration completed = smsAccepted.get().complete();
        return switch (registrations.complete(completed)) {
            case COMPLETED -> new RegisterCustomerResult.Ready(completed.id(), completed.customerId(),
                    completed.userName(), true);
            case IDENTITY_TAKEN -> {
                registrations.save(smsAccepted.get().fail());
                yield new RegisterCustomerResult.IdentityConflict();
            }
            case STALE -> new RegisterCustomerResult.Unavailable();
        };
    }
}
