package com.vpbank.dcp.infrastructure.adapter.in.web.password;

import com.vpbank.dcp.core.port.in.password.PasswordLoginUseCase;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Objects;

/**
 * This route is private to the mTLS-authenticated Mobile BFF, never App-facing.
 */
@RestController
@ConditionalOnWebApplication
@RequestMapping("/internal/v1/authentications")
public final class PasswordLoginController {
    private final PasswordLoginRequestMapper requests;
    private final PasswordLoginUseCase passwords;
    private final PasswordLoginResponseMapper responses;

    public PasswordLoginController(PasswordLoginRequestMapper requests,
                                   PasswordLoginUseCase passwords,
                                   PasswordLoginResponseMapper responses) {
        this.requests = Objects.requireNonNull(requests);
        this.passwords = Objects.requireNonNull(passwords);
        this.responses = Objects.requireNonNull(responses);
    }

    @PostMapping(path = "/password", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> login(@RequestBody PasswordLoginRequest forwarded) {
        var command = requests.map(forwarded);
        return responses.map(command.operation().operationId(), passwords.login(command));
    }
}
