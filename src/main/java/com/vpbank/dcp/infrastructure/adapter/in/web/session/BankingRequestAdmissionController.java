package com.vpbank.dcp.infrastructure.adapter.in.web.session;

import com.vpbank.dcp.core.port.in.session.BankingRequestAdmissionResult;
import com.vpbank.dcp.core.port.in.session.BankingRequestAdmissionUseCase;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@ConditionalOnWebApplication
public final class BankingRequestAdmissionController {
    private final BankingRequestAdmissionRequestMapper mapper;
    private final BankingRequestAdmissionUseCase admissions;

    public BankingRequestAdmissionController(BankingRequestAdmissionRequestMapper mapper,
                                             BankingRequestAdmissionUseCase admissions) {
        this.mapper = Objects.requireNonNull(mapper);
        this.admissions = Objects.requireNonNull(admissions);
    }

    @PostMapping(path = "/internal/v1/admissions", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> admit(@RequestBody BankingRequestAdmissionRequest forwarded) {
        BankingRequestAdmissionResult result = admissions.admit(mapper.map(forwarded));
        if (result instanceof BankingRequestAdmissionResult.Admitted admitted) {
            return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                    .body(Map.of("customerContext", admitted.customerContext(),
                            "idleExpiresAt", admitted.deadlines().idleExpiresAt().toString(),
                            "absoluteExpiresAt", admitted.deadlines().absoluteExpiresAt().toString(),
                            "dpopNonce", admitted.dpopNonce()));
        }
        if (result instanceof BankingRequestAdmissionResult.NonceRequired required) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).cacheControl(CacheControl.noStore())
                    .header("DPoP-Nonce", required.nonce())
                    .body(problem("REQUEST_REJECTED"));
        }
        if (result instanceof BankingRequestAdmissionResult.Unavailable) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .cacheControl(CacheControl.noStore())
                    .body(problem("TEMPORARILY_UNAVAILABLE"));
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).cacheControl(CacheControl.noStore())
                .body(problem("REQUEST_REJECTED"));
    }

    private Map<String, Object> problem(String code) {
        return Map.of("code", code, "message", "The request was rejected",
                "correlationId", UUID.randomUUID().toString());
    }
}
