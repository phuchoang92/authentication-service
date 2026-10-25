package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.command.RegisterCustomerCommand;
import com.vpbank.dcp.auth.application.port.in.RegisterCustomerUseCase;
import com.vpbank.dcp.auth.application.port.out.exception.PartnerUnavailableException;
import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.port.out.gateway.CustomerDirectoryPort;
import com.vpbank.dcp.auth.application.port.out.gateway.IdentityProviderPort;
import com.vpbank.dcp.auth.application.port.out.gateway.IdentityProviderPort.CreateUserResult;
import com.vpbank.dcp.auth.application.port.out.gateway.SmsSenderPort;
import com.vpbank.dcp.auth.application.port.out.model.CustomerProfile;
import com.vpbank.dcp.auth.application.port.out.model.InitialPasswordSms;
import com.vpbank.dcp.auth.application.port.out.model.NewIdentityUser;
import com.vpbank.dcp.auth.application.port.out.repository.RegistrationRepository;
import com.vpbank.dcp.auth.application.port.out.repository.RegistrationRepository.CompleteResult;
import com.vpbank.dcp.auth.application.port.out.repository.RegistrationRepository.ReserveResult;
import com.vpbank.dcp.auth.application.result.RegisterCustomerResult;
import com.vpbank.dcp.auth.domain.enums.RegistrationState;
import com.vpbank.dcp.auth.domain.model.Registration;
import com.vpbank.dcp.auth.domain.model.RegistrationId;
import com.vpbank.dcp.auth.domain.model.RequestDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

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
    /** The first result the app can learn after a successful registration is "created now". */
    private static final boolean CREATED_NOW = true;
    private static final boolean CREATED_EARLIER = false;

    @NonNull private final RegistrationRepository registrationRepository;
    @NonNull private final CustomerDirectoryPort customerDirectoryPort;
    @NonNull private final IdentityProviderPort identityProviderPort;
    @NonNull private final SmsSenderPort smsSenderPort;
    @NonNull private final RequestDigester requestDigester;
    @NonNull private final InitialPasswordGenerator initialPasswordGenerator;
    @NonNull private final Clock clock;
    @NonNull private final Duration requestLifetime;
    @NonNull private final Supplier<RegistrationId> registrationIdGenerator;

    @Override
    public RegisterCustomerResult register(RegisterCustomerCommand command) {
        Objects.requireNonNull(command, "command");
        RequestDigest requestDigest = requestDigester.digest(command);

        try {
            Optional<Registration> latestRegistration = registrationRepository.findLatest(command.customerId());
            Optional<RegisterCustomerResult> answerForLatest = latestRegistration
                    .flatMap(earlier -> answerForEarlier(earlier, requestDigest));
            if (answerForLatest.isPresent()) {
                return answerForLatest.get();
            }

            if (!profileMatches(command)) {
                return new RegisterCustomerResult.ProfileIncomplete();
            }

            Instant requestExpiresAt = clock.instant().plus(requestLifetime);
            Registration freshRegistration = Registration.reserve(
                    registrationIdGenerator.get(),
                    command.customerId(),
                    command.userName(),
                    requestDigest,
                    requestExpiresAt);

            ReserveResult reserveResult = registrationRepository.reserve(freshRegistration);
            return switch (reserveResult) {
                case ReserveResult.Reserved(Registration reservedRegistration) ->
                        createAccount(command, reservedRegistration);
                case ReserveResult.CustomerHasOpen(Registration openRegistration) ->
                        answerForEarlier(openRegistration, requestDigest)
                                .orElseGet(RegisterCustomerResult.Unavailable::new);
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
    private static Optional<RegisterCustomerResult> answerForEarlier(Registration earlierRegistration,
                                                                     RequestDigest requestDigest) {
        if (earlierRegistration.state() == RegistrationState.FAILED) {
            return Optional.empty();
        }

        if (!earlierRegistration.isSameRequest(requestDigest)) {
            return Optional.of(new RegisterCustomerResult.IdentityConflict());
        }

        if (earlierRegistration.state() == RegistrationState.READY) {
            RegisterCustomerResult.Ready readyEarlier = new RegisterCustomerResult.Ready(
                    earlierRegistration.id(),
                    earlierRegistration.customerId(),
                    earlierRegistration.userName(),
                    CREATED_EARLIER);
            return Optional.of(readyEarlier);
        }

        // Same data, still open: an earlier attempt is in progress or its outcome is unknown.
        return Optional.of(new RegisterCustomerResult.Unavailable());
    }

    /** ELIGIBLE, and the phone (and email, when sent) is the one the Customer service verified. */
    private boolean profileMatches(RegisterCustomerCommand command) {
        Optional<CustomerProfile> foundProfile = customerDirectoryPort.profile(command.customerId());
        if (foundProfile.isEmpty()) {
            return false;
        }
        CustomerProfile profile = foundProfile.get();

        boolean emailMatches = command.email() == null
                || (profile.emailVerified() && command.email().sameAs(profile.email()));
        boolean phoneMatches = profile.phoneVerified()
                && command.phoneNumber().value().equals(profile.phone());

        return profile.eligible() && phoneMatches && emailMatches;
    }

    private RegisterCustomerResult createAccount(RegisterCustomerCommand command, Registration reservedRegistration) {
        NewIdentityUser newIdentityUser = NewIdentityUser.builder()
                .userName(command.userName())
                .firstName(command.firstName())
                .lastName(command.lastName())
                .email(command.email())
                .emailVerified(command.email() != null)
                .build();

        CreateUserResult createUserResult = identityProviderPort.createDisabledUser(newIdentityUser);
        if (createUserResult instanceof CreateUserResult.UserNameTaken) {
            Registration failedRegistration = reservedRegistration.fail();
            registrationRepository.save(failedRegistration);
            return new RegisterCustomerResult.IdentityConflict();
        }
        CreateUserResult.Created createdUser = (CreateUserResult.Created) createUserResult;

        Registration userCreatedRegistration = reservedRegistration.markUserCreated(
                createdUser.identityIssuer(),
                createdUser.identitySubject());
        Optional<Registration> savedUserCreated = registrationRepository.save(userCreatedRegistration);
        if (savedUserCreated.isEmpty()) {
            return new RegisterCustomerResult.Unavailable();
        }

        String initialPassword = initialPasswordGenerator.next();
        identityProviderPort.setPassword(createdUser.identitySubject(), initialPassword);

        InitialPasswordSms initialPasswordSms = InitialPasswordSms.builder()
                .messageId(reservedRegistration.id())
                .customerId(command.customerId())
                .phone(command.phoneNumber())
                .userName(command.userName())
                .password(initialPassword)
                .build();
        boolean smsAccepted = smsSenderPort.sendInitialPassword(initialPasswordSms);
        if (!smsAccepted) {
            return new RegisterCustomerResult.Unavailable();
        }

        Registration smsAcceptedRegistration = savedUserCreated.get().markSmsAccepted();
        Optional<Registration> savedSmsAccepted = registrationRepository.save(smsAcceptedRegistration);
        if (savedSmsAccepted.isEmpty()) {
            return new RegisterCustomerResult.Unavailable();
        }

        identityProviderPort.enable(createdUser.identitySubject());

        Registration completedRegistration = savedSmsAccepted.get().complete();
        CompleteResult completeResult = registrationRepository.complete(completedRegistration);
        return switch (completeResult) {
            case COMPLETED -> new RegisterCustomerResult.Ready(
                    completedRegistration.id(),
                    completedRegistration.customerId(),
                    completedRegistration.userName(),
                    CREATED_NOW);
            case IDENTITY_TAKEN -> {
                Registration failedRegistration = savedSmsAccepted.get().fail();
                registrationRepository.save(failedRegistration);
                yield new RegisterCustomerResult.IdentityConflict();
            }
            case STALE -> new RegisterCustomerResult.Unavailable();
        };
    }
}
