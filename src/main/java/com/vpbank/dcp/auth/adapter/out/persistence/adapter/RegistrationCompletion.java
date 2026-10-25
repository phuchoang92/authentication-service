package com.vpbank.dcp.auth.adapter.out.persistence.adapter;

import com.vpbank.dcp.auth.adapter.out.persistence.entity.RegistrationEntity;
import com.vpbank.dcp.auth.adapter.out.persistence.mapper.RegistrationPersistenceMapper;
import com.vpbank.dcp.auth.adapter.out.persistence.repository.CustomerAuthenticationJpaRepository;
import com.vpbank.dcp.auth.adapter.out.persistence.repository.RegistrationJpaRepository;
import com.vpbank.dcp.auth.application.port.out.RegistrationRepository.CompleteResult;
import com.vpbank.dcp.auth.domain.model.Registration;
import com.vpbank.dcp.auth.domain.model.RegistrationState;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

/**
 * The one step that writes two tables together: the identity row and the READY state. Kept in
 * its own bean so the transaction proxy wraps exactly this method and the adapter can translate
 * failures outside it. The conflict is pre-checked by query, so this method returns a result;
 * a lost race on UQ_CA_USER_NAME propagates and rolls everything back.
 */
@RequiredArgsConstructor
public class RegistrationCompletion {
    @NonNull private final RegistrationJpaRepository registrations;
    @NonNull private final CustomerAuthenticationJpaRepository identities;

    @Transactional
    public CompleteResult complete(Registration completed) {
        Optional<RegistrationEntity> locked = registrations.lockByRequestId(completed.id().value());
        if (locked.isEmpty() || locked.get().getVersion() != completed.version()
                || locked.get().getState() != RegistrationState.SMS_ACCEPTED) {
            return CompleteResult.STALE;
        }
        if (identities.existsByUserNameIgnoreCase(completed.userName().value())) {
            return CompleteResult.IDENTITY_TAKEN;
        }
        identities.save(RegistrationPersistenceMapper.toIdentity(completed));
        RegistrationPersistenceMapper.apply(locked.get(), completed);
        registrations.flush();
        return CompleteResult.COMPLETED;
    }
}
