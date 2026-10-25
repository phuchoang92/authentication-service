package com.vpbank.dcp.auth.infrastructure.adapter.in.web.registration;

import com.vpbank.dcp.auth.core.customer.CustomerRegistrationService;
import com.vpbank.dcp.auth.core.customer.RegistrationCommand;
import com.vpbank.dcp.auth.core.customer.RegistrationResult;
import com.vpbank.dcp.auth.infrastructure.adapter.in.web.ApiEnvelope;
import jakarta.validation.Valid;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Objects;
import java.util.UUID;

/**
 * Customer → Auth: create the login account of an onboarded customer (contract §1). Called by
 * the Customer service only; it is off unless {@code auth.registration.enabled=true}, because the
 * caller is not authenticated yet.
 */
@RestController
@ConditionalOnProperty(prefix = "auth.registration", name = "enabled", havingValue = "true")
public class RegistrationController {
    private final CustomerRegistrationService registrations;

    public RegistrationController(CustomerRegistrationService registrations) {
        this.registrations = Objects.requireNonNull(registrations);
    }

    @PostMapping(path = "/internal/v1/callback/authentication-creation",
            consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> create(@Valid @RequestBody RegistrationRequest body) {
        RegistrationCommand command = new RegistrationCommand(body.customerId(), body.userName(),
                body.firstName(), body.lastName(), body.phoneNumber(), body.email());
        return switch (registrations.register(command)) {
            case RegistrationResult.Ready ready -> ResponseEntity
                    .status(ready.created() ? HttpStatus.CREATED : HttpStatus.OK)
                    .body(ApiEnvelope.success(new Created(ready.requestId(), ready.customerId(),
                            ready.userName(), "READY")));
            case RegistrationResult.IdentityConflict() -> ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(ApiEnvelope.failure("IDENTITY_CONFLICT",
                            "The customer or user name is linked to another identity"));
            case RegistrationResult.ProfileIncomplete() -> ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(ApiEnvelope.failure("CUSTOMER_PROFILE_INCOMPLETE",
                            "The customer profile does not allow account creation"));
            case RegistrationResult.Unavailable() -> ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .body(ApiEnvelope.failure("ACCOUNT_CREATION_UNAVAILABLE",
                            "Authentication account creation could not be completed"));
        };
    }

    record Created(UUID requestId, String customerId, String userName, String state) { }
}
