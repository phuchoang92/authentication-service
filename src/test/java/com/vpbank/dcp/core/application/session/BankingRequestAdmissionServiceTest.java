package com.vpbank.dcp.core.application.session;

import com.vpbank.dcp.core.application.password.PasswordAvailabilityPolicy;
import com.vpbank.dcp.core.port.in.session.BankingRequestAdmissionCommand;
import com.vpbank.dcp.core.port.in.session.BankingRequestAdmissionResult;
import com.vpbank.dcp.core.port.out.session.BankingSessionAdmissionStore;
import com.vpbank.dcp.core.port.out.session.CustomerContextSigner;
import com.vpbank.dcp.core.port.out.session.SessionProofVerifier;
import java.time.Clock;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

class BankingRequestAdmissionServiceTest {

    @Test
    void productionGateClosesBeforeReadingSession() {
        BankingSessionAdmissionStore sessions = mock(BankingSessionAdmissionStore.class);
        SessionProofVerifier proofs = mock(SessionProofVerifier.class);
        CustomerContextSigner contexts = mock(CustomerContextSigner.class);
        BankingRequestAdmissionCommand command = mock(BankingRequestAdmissionCommand.class);
        var service = new BankingRequestAdmissionService(sessions, proofs, contexts,
                Clock.systemUTC(), new PasswordAvailabilityPolicy(false));

        assertThat(service.admit(command))
                .isInstanceOf(BankingRequestAdmissionResult.Unavailable.class);
        verifyNoInteractions(sessions, proofs, contexts, command);
    }
}
