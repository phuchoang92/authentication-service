package com.vpbank.dcp.auth.adapter.in.web.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/** Contract §1 request. Sizes follow the database columns; messages come from ValidationMessages_<lang>. */
public record RegistrationRequest(
        @NotBlank(message = "{auth.required}")
        @Pattern(regexp = "[A-Za-z0-9]{1,16}", message = "{auth.format}")
        String customerId,
        @NotBlank(message = "{auth.required}")
        @Pattern(regexp = "[A-Za-z0-9._-]{3,64}", message = "{auth.format}")
        String userName,
        @NotBlank(message = "{auth.required}") @Size(max = 100, message = "{auth.tooLong}") String firstName,
        @NotBlank(message = "{auth.required}") @Size(max = 100, message = "{auth.tooLong}") String lastName,
        @NotBlank(message = "{auth.required}")
        @Pattern(regexp = "\\+[1-9][0-9]{7,14}", message = "{auth.format}")
        String phoneNumber,
        @Email(message = "{auth.format}") @Size(max = 255, message = "{auth.tooLong}") String email) {

    @Override
    public String toString() {
        return "RegistrationRequest[customerId=" + customerId + ", redacted]";
    }
}
