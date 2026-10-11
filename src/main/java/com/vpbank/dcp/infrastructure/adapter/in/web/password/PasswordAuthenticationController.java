package com.vpbank.dcp.infrastructure.adapter.in.web.password;

import com.vpbank.dcp.core.port.in.password.AuthenticateWithPassword;
import java.util.Objects;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** This route is private to the mTLS-authenticated Mobile BFF, never App-facing. */
@RestController
@RequestMapping("/internal/v1/authentications")
public final class PasswordAuthenticationController {
    private final ForwardPasswordRequestMapper requests;
    private final AuthenticateWithPassword passwords;
    private final PasswordHttpResponseMapper responses;

    public PasswordAuthenticationController(ForwardPasswordRequestMapper requests,
                                            AuthenticateWithPassword passwords,
                                            PasswordHttpResponseMapper responses) {
        this.requests = Objects.requireNonNull(requests);
        this.passwords = Objects.requireNonNull(passwords);
        this.responses = Objects.requireNonNull(responses);
    }

    @PostMapping(path = "/password", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> authenticate(@RequestBody ForwardPasswordRequest forwarded) {
        var command = requests.map(forwarded);
        return responses.map(command.operation().operationId(), passwords.authenticate(command));
    }
}
