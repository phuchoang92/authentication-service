package com.vpbank.dcp.infrastructure.adapter.in.web.password.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import tools.jackson.databind.annotation.JsonDeserialize;
import tools.jackson.databind.annotation.JsonPOJOBuilder;

/**
 * Direct JSON body. Credentials are input-only and absent from diagnostic output.
 */
@JsonDeserialize(builder = PasswordLoginRequest.Builder.class)
public final class PasswordLoginRequest {
    @JsonProperty
    @NotNull
    @Pattern(regexp = "neo-mobile")
    private final String appId;
    @JsonProperty
    @NotNull
    @Pattern(regexp = "ANDROID|IOS")
    private final String platform;
    @JsonProperty
    @NotNull
    @Size(min = 16, max = 300)
    private final String installationId;
    @JsonProperty
    @NotBlank
    @Size(max = 320)
    private final String username;
    @NotNull
    @Size(min = 1, max = 1024)
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private final String password;
    @JsonProperty
    @Size(min = 16, max = 300)
    private final String deviceBindingId;
    @JsonProperty
    @NotNull
    @Valid
    private final TokenEncryptionKeyRequest tokenEncryptionKey;
    @JsonProperty
    @NotNull
    @Size(min = 64, max = 8192)
    private final String requestKeyProof;
    @JsonProperty
    @Size(min = 64, max = 8192)
    private final String deviceProof;

    private PasswordLoginRequest(Builder builder) {
        this.appId = builder.appId;
        this.platform = builder.platform;
        this.installationId = builder.installationId;
        this.username = builder.username;
        this.password = builder.password;
        this.deviceBindingId = builder.deviceBindingId;
        this.tokenEncryptionKey = builder.tokenEncryptionKey;
        this.requestKeyProof = builder.requestKeyProof;
        this.deviceProof = builder.deviceProof;
    }

    public static Builder builder() {
        return new Builder();
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

    public TokenEncryptionKeyRequest tokenEncryptionKey() {
        return tokenEncryptionKey;
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

    @JsonPOJOBuilder(withPrefix = "")
    public static final class Builder {
        private String appId;
        private String platform;
        private String installationId;
        private String username;
        private String password;
        private String deviceBindingId;
        private TokenEncryptionKeyRequest tokenEncryptionKey;
        private String requestKeyProof;
        private String deviceProof;

        public Builder appId(String appId) {
            this.appId = appId;
            return this;
        }

        public Builder platform(String platform) {
            this.platform = platform;
            return this;
        }

        public Builder installationId(String installationId) {
            this.installationId = installationId;
            return this;
        }

        public Builder username(String username) {
            this.username = username;
            return this;
        }

        public Builder password(String password) {
            this.password = password;
            return this;
        }

        public Builder deviceBindingId(String deviceBindingId) {
            this.deviceBindingId = deviceBindingId;
            return this;
        }

        public Builder tokenEncryptionKey(TokenEncryptionKeyRequest tokenEncryptionKey) {
            this.tokenEncryptionKey = tokenEncryptionKey;
            return this;
        }

        public Builder requestKeyProof(String requestKeyProof) {
            this.requestKeyProof = requestKeyProof;
            return this;
        }

        public Builder deviceProof(String deviceProof) {
            this.deviceProof = deviceProof;
            return this;
        }

        public PasswordLoginRequest build() {
            return new PasswordLoginRequest(this);
        }

        @Override
        public String toString() {
            return "PasswordLoginRequest.Builder[redacted]";
        }
    }
}
