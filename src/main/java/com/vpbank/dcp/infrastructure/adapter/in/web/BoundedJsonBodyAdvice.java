package com.vpbank.dcp.infrastructure.adapter.in.web;

import com.vpbank.dcp.infrastructure.adapter.in.web.password.PasswordLoginController;
import com.vpbank.dcp.infrastructure.adapter.in.web.trusteddevice.TrustedDeviceController;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Type;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.RequestBodyAdviceAdapter;

/**
 * Bounds direct JSON input before parsing, including chunked requests.
 */
@ControllerAdvice(assignableTypes = {PasswordLoginController.class, TrustedDeviceController.class})
public final class BoundedJsonBodyAdvice extends RequestBodyAdviceAdapter {
    private static final int MAX_BODY_BYTES = 65_536;

    @Override
    public boolean supports(MethodParameter parameter, Type targetType,
                            Class<? extends HttpMessageConverter<?>> converterType) {
        return true;
    }

    @Override
    public HttpInputMessage beforeBodyRead(HttpInputMessage input, MethodParameter parameter,
                                           Type targetType,
                                           Class<? extends HttpMessageConverter<?>> converterType) throws IOException {
        if (input.getHeaders().getContentLength() > MAX_BODY_BYTES
                || input.getHeaders().containsHeader(HttpHeaders.CONTENT_ENCODING)) {
            throw new HttpMessageNotReadableException("The request was rejected", input);
        }
        byte[] body = input.getBody().readNBytes(MAX_BODY_BYTES + 1);
        if (body.length > MAX_BODY_BYTES) {
            throw new HttpMessageNotReadableException("The request was rejected", input);
        }
        return new HttpInputMessage() {
            @Override
            public InputStream getBody() {
                return new ByteArrayInputStream(body);
            }

            @Override
            public HttpHeaders getHeaders() {
                return input.getHeaders();
            }
        };
    }
}
