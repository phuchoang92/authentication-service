package com.vpbank.dcp.auth.infrastructure.adapter.in.web.registration;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/** Contract §1 request. Sizes follow the database columns. */
public record RegistrationRequest(
        @NotBlank @Pattern(regexp = "[A-Za-z0-9]{1,16}", message = "must match the required format")
        String customerId,
        @NotBlank @Pattern(regexp = "[A-Za-z0-9._-]{3,64}", message = "must match the required format")
        String userName,
        @NotBlank @Size(max = 100) String firstName,
        @NotBlank @Size(max = 100) String lastName,
        @NotBlank @Pattern(regexp = "\\+[1-9][0-9]{7,14}", message = "must match the required format")
        String phoneNumber,
        @Email @Size(max = 255) String email) {

    @Override
    public String toString() {
        return "RegistrationRequest[customerId=" + customerId + ", redacted]";
    }
}
