package com.vpbank.dcp.infrastructure.adapter.in.web.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.vpbank.dcp.infrastructure.adapter.in.web.InvalidWorkloadIdentityConfigurationException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

class WorkloadUriPrincipalExtractorTest {
    private static final String URI = "spiffe://bank.test/mobile-bff";
    private final WorkloadUriPrincipalExtractor extractor = new WorkloadUriPrincipalExtractor(Set.of(URI));

    @Test
    void acceptsOnlyAnExactAllowedUriSanIncludingLaterEntries() throws Exception {
        var certificate = mock(X509Certificate.class);
        when(certificate.getSubjectAlternativeNames()).thenReturn(List.of(
                List.of(6, URI + "-attacker"), List.of(2, URI), List.of(6, URI)));
        assertThat(extractor.extractPrincipal(certificate)).isEqualTo(URI);
        when(certificate.getSubjectAlternativeNames()).thenReturn(List.of(List.of(2, URI)));
        assertThat(extractor.extractPrincipal(certificate)).isNull();
        when(certificate.getSubjectAlternativeNames()).thenReturn(List.of(List.of(6, URI + "/")));
        assertThat(extractor.extractPrincipal(certificate)).isNull();
    }

    @Test
    void rejectsMissingMalformedExpiredOrNotYetValidCertificateIdentity() throws Exception {
        var certificate = mock(X509Certificate.class);
        assertThat(extractor.extractPrincipal(certificate)).isNull();
        when(certificate.getSubjectAlternativeNames()).thenThrow(new CertificateParsingException());
        assertThat(extractor.extractPrincipal(certificate)).isNull();
        doThrow(new CertificateExpiredException()).when(certificate).checkValidity();
        assertThat(extractor.extractPrincipal(certificate)).isNull();
        doThrow(new CertificateNotYetValidException()).when(certificate).checkValidity();
        assertThat(extractor.extractPrincipal(certificate)).isNull();
    }

    @Test
    void emptyAllowlistFailsStartup() {
        assertThatThrownBy(() -> new WorkloadUriPrincipalExtractor(Set.of()))
                .isInstanceOf(InvalidWorkloadIdentityConfigurationException.class);
    }
}
