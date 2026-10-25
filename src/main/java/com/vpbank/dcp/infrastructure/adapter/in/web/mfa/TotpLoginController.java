package com.vpbank.dcp.infrastructure.adapter.in.web.mfa;

import com.vpbank.dcp.core.port.in.mfa.CompleteTotpLoginUseCase;
import com.vpbank.dcp.core.port.in.mfa.TotpLoginResult;
import com.vpbank.dcp.core.port.in.password.PasswordLoginResult;
import com.vpbank.dcp.infrastructure.adapter.in.web.mfa.dto.TotpLoginProofRequest;
import com.vpbank.dcp.infrastructure.adapter.in.web.password.PasswordLoginResponseMapper;
import com.vpbank.dcp.infrastructure.adapter.in.web.password.dto.PasswordLoginResponse;
import jakarta.validation.Valid;
import java.util.Objects;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Private BFF-only generic challenge route currently accepts only LOGIN_TOTP. */
@RestController
@ConditionalOnProperty(prefix = "auth.native-session", name = "integration-activation-enabled",
        havingValue = "true")
@RequestMapping("/internal/v1/mfa/challenges")
public final class TotpLoginController {
    private final TotpLoginRequestVerifier requests;
    private final CompleteTotpLoginUseCase logins;
    private final PasswordLoginResponseMapper responses;

    public TotpLoginController(TotpLoginRequestVerifier requests, CompleteTotpLoginUseCase logins,
                               PasswordLoginResponseMapper responses) {
        this.requests = Objects.requireNonNull(requests);
        this.logins = Objects.requireNonNull(logins);
        this.responses = Objects.requireNonNull(responses);
    }

    @PostMapping(path = "/{challengeId}/verify", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<PasswordLoginResponse> verify(@PathVariable String challengeId,
            @RequestHeader("Authorization") String authorization,
            @RequestHeader("DPoP") String dpop,
            @Valid @RequestBody TotpLoginProofRequest body) {
        try {
            var command = requests.verify(challengeId, authorization, dpop, body.proof());
            TotpLoginResult result = logins.complete(command);
            if (result instanceof TotpLoginResult.Active active) {
                return responses.map(new PasswordLoginResult.Active(active.session()));
            }
            return responses.map(result instanceof TotpLoginResult.Rejected
                    ? new PasswordLoginResult.Rejected()
                    : new PasswordLoginResult.TemporarilyUnavailable());
        } catch (InvalidTotpLoginRequestException failure) {
            return responses.map(new PasswordLoginResult.Rejected());
        } catch (TotpLoginRequestUnavailableException failure) {
            return responses.map(new PasswordLoginResult.TemporarilyUnavailable());
        }
    }
}
