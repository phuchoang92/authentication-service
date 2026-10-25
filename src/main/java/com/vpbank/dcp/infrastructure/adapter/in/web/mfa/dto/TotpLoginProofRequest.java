package com.vpbank.dcp.infrastructure.adapter.in.web.mfa.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record TotpLoginProofRequest(@NotBlank @Size(min = 100, max = 8192) String proof) {
    @Override
    public String toString() {
        return "TotpLoginProofRequest[redacted]";
    }
}
