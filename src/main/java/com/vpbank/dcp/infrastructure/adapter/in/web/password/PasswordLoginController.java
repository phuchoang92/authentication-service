package com.vpbank.dcp.infrastructure.adapter.in.web.password;

import com.vpbank.dcp.core.password.PasswordLoginResult;
import com.vpbank.dcp.core.password.PasswordLoginService;
import com.vpbank.dcp.core.security.VerifiedDpopProof;
import com.vpbank.dcp.infrastructure.adapter.in.web.password.dto.PasswordLoginRequest;
import com.vpbank.dcp.infrastructure.adapter.in.web.password.dto.PasswordLoginResponse;
import com.vpbank.dcp.infrastructure.adapter.in.web.security.constant.DpopRequestAttributes;
import jakarta.validation.Valid;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Objects;

/**
 * This route is private to the mTLS-authenticated Mobile BFF, never App-facing.
 *
 * <p>{@link PasswordLoginService} exists only with the integration profile and activation flag;
 * without it every login answers temporarily unavailable, so production stays fail-closed.
 */
@RestController
@ConditionalOnWebApplication
@RequestMapping("/internal/v1/authentications")
public final class PasswordLoginController {
    private final PasswordLoginRequestMapper requests;
    private final ObjectProvider<PasswordLoginService> passwords;
    private final PasswordLoginResponseMapper responses;

    public PasswordLoginController(PasswordLoginRequestMapper requests,
                                   ObjectProvider<PasswordLoginService> passwords,
                                   PasswordLoginResponseMapper responses) {
        this.requests = Objects.requireNonNull(requests);
        this.passwords = Objects.requireNonNull(passwords);
        this.responses = Objects.requireNonNull(responses);
    }

    @PostMapping(path = "/password",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<PasswordLoginResponse> login(@RequestHeader HttpHeaders headers,
                                                       @Valid @RequestBody PasswordLoginRequest body,
                                                       @RequestAttribute(DpopRequestAttributes.VERIFIED_DPOP_PROOF) VerifiedDpopProof dpop) {
        var command = requests.map(PasswordLoginHeaders.from(headers), body, dpop);
        PasswordLoginService service = passwords.getIfAvailable();
        return responses.map(service == null
                ? new PasswordLoginResult.TemporarilyUnavailable() : service.login(command));
    }
}
