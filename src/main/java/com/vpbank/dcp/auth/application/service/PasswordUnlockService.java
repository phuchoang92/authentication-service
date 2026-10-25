package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.result.UnlockPasswordResult;
import com.vpbank.dcp.auth.application.port.in.UnlockPasswordUseCase;
import com.vpbank.dcp.auth.application.port.out.repository.CustomerAuthenticationRepository;
import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/** The bank's unlock after a permanent (or any) password lock. Idempotent: an unlocked account stays unlocked. */
@RequiredArgsConstructor
public final class PasswordUnlockService implements UnlockPasswordUseCase {
    @NonNull private final CustomerAuthenticationRepository identities;

    @Override
    public UnlockPasswordResult unlock(CustomerId customerId) {
        try {
            return identities.unlock(customerId) ? new UnlockPasswordResult.Unlocked()
                    : new UnlockPasswordResult.UnknownCustomer();
        } catch (RepositoryUnavailableException failure) {
            return new UnlockPasswordResult.Unavailable();
        }
    }
}
