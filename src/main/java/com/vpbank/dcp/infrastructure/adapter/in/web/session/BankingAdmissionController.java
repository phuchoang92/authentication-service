package com.vpbank.dcp.infrastructure.adapter.in.web.session;

import com.vpbank.dcp.core.application.session.BankingAdmissionDecision;
import com.vpbank.dcp.core.port.in.session.AdmitBankingRequest;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public final class BankingAdmissionController {
    private final ForwardAdmissionMapper mapper;
    private final AdmitBankingRequest admissions;

    public BankingAdmissionController(ForwardAdmissionMapper mapper, AdmitBankingRequest admissions) {
        this.mapper = Objects.requireNonNull(mapper);
        this.admissions = Objects.requireNonNull(admissions);
    }

    @PostMapping(path = "/internal/v1/admissions", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> admit(@RequestBody ForwardAdmissionRequest forwarded) {
        BankingAdmissionDecision decision = admissions.admit(mapper.map(forwarded));
        if (decision instanceof BankingAdmissionDecision.Admitted admitted) {
            return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                    .body(Map.of("customerContext", admitted.customerContext(),
                            "idleExpiresAt", admitted.deadlines().idleExpiresAt().toString(),
                            "absoluteExpiresAt", admitted.deadlines().absoluteExpiresAt().toString(),
                            "dpopNonce", admitted.dpopNonce()));
        }
        if (decision instanceof BankingAdmissionDecision.NonceRequired required) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).cacheControl(CacheControl.noStore())
                    .header("DPoP-Nonce", required.nonce())
                    .body(problem("REQUEST_REJECTED"));
        }
        if (decision instanceof BankingAdmissionDecision.Unavailable) {
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
