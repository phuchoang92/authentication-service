package com.vpbank.dcp.auth.application.command;

import com.vpbank.dcp.auth.domain.model.OpaqueToken;
import lombok.NonNull;

/** The session to end, named by the token the app presented. */
public record LogoutCommand(@NonNull OpaqueToken token) {
}
