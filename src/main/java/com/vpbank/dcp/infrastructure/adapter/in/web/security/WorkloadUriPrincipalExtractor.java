package com.vpbank.dcp.infrastructure.adapter.in.web.security;

import com.vpbank.dcp.infrastructure.adapter.in.web.InvalidWorkloadIdentityConfigurationException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Collection;
import java.util.Objects;
import java.util.Set;
import org.springframework.security.web.authentication.preauth.x509.X509PrincipalExtractor;

/** TLS verifies certificate trust; Auth authorizes exact URI SANs rather than certificate CNs. */
public final class WorkloadUriPrincipalExtractor implements X509PrincipalExtractor {
    private final Set<String> allowedUris;

    public WorkloadUriPrincipalExtractor(Set<String> allowedUris) {
        this.allowedUris = Set.copyOf(Objects.requireNonNull(allowedUris, "allowedUris"));
        if (this.allowedUris.isEmpty()) {
            throw new InvalidWorkloadIdentityConfigurationException();
        }
    }

    @Override
    public Object extractPrincipal(X509Certificate certificate) {
        try {
            certificate.checkValidity();
            Collection<List<?>> names = certificate.getSubjectAlternativeNames();
            if (names != null) {
                for (List<?> name : names) {
                    if (name.size() >= 2 && Integer.valueOf(6).equals(name.getFirst())
                            && name.get(1) instanceof String uri && allowedUris.contains(uri)) {
                        return uri;
                    }
                }
            }
        } catch (CertificateException invalid) {
            return null;
        }
        return null;
    }
}
