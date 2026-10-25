package com.vpbank.dcp.auth.core.customer;

import com.vpbank.dcp.auth.core.customer.IdentityProvider.CreateUserResult;
import com.vpbank.dcp.auth.core.customer.RegistrationStore.ReserveResult;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;

/**
 * Creates the login account of a customer who finished onboarding (contract §1):
 * reserve → check Customer → create the Keycloak user disabled → set its password →
 * SMS accepted → enable → write the identity and READY.
 *
 * <p>The order is a security rule: nobody can log in before Notification accepted the SMS, and
 * the identity row exists only once the account is usable. Each step is recorded before the next
 * one starts. If a step fails or its outcome is unknown, the request stays where it is and a
 * retry returns UNAVAILABLE: it never calls Keycloak or Notification again blindly.
 */
public final class CustomerRegistrationService {
    private final RegistrationStore store;
    private final CustomerDirectory customers;
    private final IdentityProvider identities;
    private final SmsSender sms;
    private final RequestDigester digester;
    private final InitialPasswordGenerator passwords;
    private final Clock clock;
    private final Duration requestLifetime;
    private final Supplier<UUID> requestIds;

    public CustomerRegistrationService(RegistrationStore store, CustomerDirectory customers,
                                       IdentityProvider identities, SmsSender sms,
                                       RequestDigester digester, InitialPasswordGenerator passwords,
                                       Clock clock, Duration requestLifetime, Supplier<UUID> requestIds) {
        this.store = Objects.requireNonNull(store);
        this.customers = Objects.requireNonNull(customers);
        this.identities = Objects.requireNonNull(identities);
        this.sms = Objects.requireNonNull(sms);
        this.digester = Objects.requireNonNull(digester);
        this.passwords = Objects.requireNonNull(passwords);
        this.clock = Objects.requireNonNull(clock);
        this.requestLifetime = Objects.requireNonNull(requestLifetime);
        this.requestIds = Objects.requireNonNull(requestIds);
        if (requestLifetime.isNegative() || requestLifetime.isZero()) {
            throw new IllegalArgumentException("Registration request lifetime must be positive");
        }
    }

    public RegistrationResult register(RegistrationCommand command) {
        Objects.requireNonNull(command, "command");
        RequestDigest digest = digester.digest(command);
        try {
            Optional<RegistrationResult> earlier = store.findLatest(command.customerId())
                    .flatMap(previous -> answerForEarlier(previous, digest));
            if (earlier.isPresent()) {
                return earlier.get();
            }
            if (!profileMatches(command)) {
                return new RegistrationResult.ProfileIncomplete();
            }
            Instant now = clock.instant();
            ReserveResult reserved = store.reserve(requestIds.get(), command.customerId(),
                    command.userName(), digest, now.plus(requestLifetime), now);
            return switch (reserved) {
                case ReserveResult.Reserved(var registration) -> createAccount(command, registration);
                case ReserveResult.CustomerHasOpen(var existing) ->
                        answerForEarlier(existing, digest).orElseGet(RegistrationResult.Unavailable::new);
                case ReserveResult.UserNameTaken() -> new RegistrationResult.IdentityConflict();
            };
        } catch (RegistrationStoreUnavailableException | PartnerUnavailableException failure) {
            return new RegistrationResult.Unavailable();
        }
    }

    /**
     * A retry or a second call for a customer who already has a request. Empty when the earlier
     * request FAILED, so a new one may start.
     */
    private static Optional<RegistrationResult> answerForEarlier(Registration earlier, RequestDigest digest) {
        if (earlier.state() == RegistrationState.FAILED) {
            return Optional.empty();
        }
        if (!earlier.requestDigest().equals(digest)) {
            return Optional.of(new RegistrationResult.IdentityConflict());
        }
        if (earlier.state() == RegistrationState.READY) {
            return Optional.of(new RegistrationResult.Ready(earlier.requestId(), earlier.customerId(),
                    earlier.userName(), false));
        }
        // Same data, still open: an earlier attempt is in progress or its outcome is unknown.
        return Optional.of(new RegistrationResult.Unavailable());
    }

    /** ELIGIBLE, and the phone (and email, when sent) is the one the Customer service verified. */
    private boolean profileMatches(RegistrationCommand command) {
        Optional<CustomerProfile> found = customers.profile(command.customerId());
        if (found.isEmpty()) {
            return false;
        }
        CustomerProfile profile = found.get();
        boolean emailOk = command.email() == null
                || (profile.emailVerified() && command.email().equalsIgnoreCase(profile.email()));
        return profile.eligible() && profile.phoneVerified()
                && command.phoneNumber().equals(profile.phone()) && emailOk;
    }

    private RegistrationResult createAccount(RegistrationCommand command, Registration registration) {
        UUID requestId = registration.requestId();
        CreateUserResult created = identities.createDisabledUser(command.userName(), command.firstName(),
                command.lastName(), command.email(), command.email() != null);
        if (created instanceof CreateUserResult.UserNameTaken) {
            store.markFailed(requestId, registration.version(), clock.instant());
            return new RegistrationResult.IdentityConflict();
        }
        var user = (CreateUserResult.Created) created;
        long version = registration.version();
        if (!store.markUserCreated(requestId, version, user.identityIssuer(), user.identitySubject(),
                clock.instant())) {
            return new RegistrationResult.Unavailable();
        }
        version++;

        String password = passwords.next();
        identities.setPassword(user.identitySubject(), password);
        if (!sms.sendInitialPassword(requestId, command.customerId(), command.phoneNumber(),
                command.userName(), password)
                || !store.markSmsAccepted(requestId, version, clock.instant())) {
            return new RegistrationResult.Unavailable();
        }
        version++;

        identities.enable(user.identitySubject());
        return switch (store.complete(requestId, version, clock.instant())) {
            case COMPLETED -> new RegistrationResult.Ready(requestId, command.customerId(),
                    command.userName(), true);
            case IDENTITY_TAKEN -> {
                store.markFailed(requestId, version, clock.instant());
                yield new RegistrationResult.IdentityConflict();
            }
            case STALE -> new RegistrationResult.Unavailable();
        };
    }
}
