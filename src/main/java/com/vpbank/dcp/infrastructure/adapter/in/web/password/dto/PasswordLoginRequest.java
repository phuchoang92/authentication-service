package com.vpbank.dcp.infrastructure.adapter.in.web.password.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Direct JSON body. Credentials are input-only and absent from diagnostic output.
 */
public final class PasswordLoginRequest {
    @NotNull
    @Pattern(regexp = "neo-mobile")
    private final String appId;
    @NotNull
    @Pattern(regexp = "ANDROID|IOS")
    private final String platform;
    @NotNull
    @Size(min = 16, max = 300)
    private final String installationId;
    @NotBlank
    @Size(max = 320)
    private final String username;
    @NotNull
    @Size(min = 1, max = 1024)
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private final String password;
    @Pattern(regexp = "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
    private final String deviceBindingId;
    @NotNull
    @Valid
    private final ResponseEncryptionKeyRequest responseKey;
    @NotNull
    @Size(min = 64, max = 8192)
    private final String requestKeyProof;
    @Size(min = 64, max = 8192)
    private final String deviceProof;

    // Constructor follows the public body; no additional credential envelope.
    @JsonCreator
    public PasswordLoginRequest(@JsonProperty("appId") String appId,
                                @JsonProperty("platform") String platform,
                                @JsonProperty("installationId") String installationId,
                                @JsonProperty("username") String username,
                                @JsonProperty("password") String password,
                                @JsonProperty("deviceBindingId") String deviceBindingId,
                                @JsonProperty("responseKey") ResponseEncryptionKeyRequest responseKey,
                                @JsonProperty("requestKeyProof") String requestKeyProof,
                                @JsonProperty("deviceProof") String deviceProof) {
        this.appId = appId;
        this.platform = platform;
        this.installationId = installationId;
        this.username = username;
        this.password = password;
        this.deviceBindingId = deviceBindingId;
        this.responseKey = responseKey;
        this.requestKeyProof = requestKeyProof;
        this.deviceProof = deviceProof;
    }

    public String appId() {
        return appId;
    }

    public String platform() {
        return platform;
    }

    public String installationId() {
        return installationId;
    }

    public String username() {
        return username;
    }

    public String password() {
        return password;
    }

    public String deviceBindingId() {
        return deviceBindingId;
    }

    public ResponseEncryptionKeyRequest responseKey() {
        return responseKey;
    }

    public String requestKeyProof() {
        return requestKeyProof;
    }

    public String deviceProof() {
        return deviceProof;
    }

    @Override
    public String toString() {
        return "PasswordLoginRequest[redacted]";
    }
}
