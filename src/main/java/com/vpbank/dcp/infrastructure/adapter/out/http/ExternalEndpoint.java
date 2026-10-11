package com.vpbank.dcp.infrastructure.adapter.out.http;

import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** An external JSON endpoint and its exact response contract. */
public final class ExternalEndpoint<T> {

    private static final Pattern VARIABLE = Pattern.compile("\\{([A-Za-z][A-Za-z0-9]*)\\}");
    private static final String ENCODED_SEGMENT = "(?:[A-Za-z0-9._~-]|%[0-9A-F]{2})+";

    private final Kind kind;
    private final String template;
    private final String path;
    private final Class<T> responseType;
    private final Set<Integer> acceptedStatuses;

    private ExternalEndpoint(Kind kind, String template, String path, Class<T> responseType,
                             Set<Integer> acceptedStatuses) {
        this.kind = kind;
        this.template = template;
        this.path = path;
        this.responseType = Objects.requireNonNull(responseType, "responseType");
        this.acceptedStatuses = Set.copyOf(acceptedStatuses);
        if (!template.startsWith("/") || template.contains("//") || template.contains("?")
                || template.contains("#") || template.contains("%") || template.contains("\\")
                || this.acceptedStatuses.isEmpty()
                || this.acceptedStatuses.stream().anyMatch(status -> status < 200 || status > 599)) {
            throw new InvalidExternalHttpSettingsException();
        }
        routePattern(template);
    }

    public static <T> ExternalEndpoint<T> getJson(String path, Class<T> responseType,
                                                   Set<Integer> acceptedStatuses) {
        return new ExternalEndpoint<>(Kind.GET_JSON, path, path, responseType, acceptedStatuses);
    }

    public static <T> ExternalEndpoint<T> postJson(String path, Class<T> responseType,
                                                    Set<Integer> acceptedStatuses) {
        return new ExternalEndpoint<>(Kind.POST_JSON, path, path, responseType, acceptedStatuses);
    }

    public static <T> ExternalEndpoint<T> postForm(String path, Class<T> responseType,
                                                    Set<Integer> acceptedStatuses) {
        return new ExternalEndpoint<>(Kind.POST_FORM, path, path, responseType, acceptedStatuses);
    }

    public ExternalEndpoint<T> bindSegment(String name, String value) {
        Objects.requireNonNull(name, "name");
        String placeholder = "{" + name + "}";
        if (!template.contains(placeholder) || !path.contains(placeholder)) {
            throw new InvalidExternalHttpSettingsException();
        }
        return new ExternalEndpoint<>(kind, template,
                path.replace(placeholder, ExternalPath.segment(value)), responseType,
                acceptedStatuses);
    }

    public ExternalHttpSettings.Route route() {
        return new ExternalHttpSettings.Route(kind.method, routePattern(template));
    }

    void requireKind(Kind expected) {
        if (kind != expected) {
            throw new InvalidExternalHttpSettingsException();
        }
    }

    String path() {
        if (path.indexOf('{') >= 0 || path.indexOf('}') >= 0) {
            throw new InvalidExternalHttpSettingsException();
        }
        return path;
    }

    Class<T> responseType() {
        return responseType;
    }

    boolean accepts(int status) {
        return acceptedStatuses.contains(status);
    }

    private static Pattern routePattern(String template) {
        Matcher matcher = VARIABLE.matcher(template);
        StringBuilder expression = new StringBuilder();
        Set<String> names = new HashSet<>();
        int from = 0;
        while (matcher.find()) {
            String prefix = template.substring(from, matcher.start());
            boolean startsSegment = matcher.start() > 0 && template.charAt(matcher.start() - 1) == '/';
            boolean endsSegment = matcher.end() == template.length()
                    || template.charAt(matcher.end()) == '/';
            if (prefix.contains("{") || prefix.contains("}")
                    || !startsSegment || !endsSegment) {
                throw new InvalidExternalHttpSettingsException();
            }
            if (!names.add(matcher.group(1))) {
                throw new InvalidExternalHttpSettingsException();
            }
            expression.append(Pattern.quote(prefix));
            expression.append(ENCODED_SEGMENT);
            from = matcher.end();
        }
        String suffix = template.substring(from);
        if (suffix.contains("{") || suffix.contains("}")) {
            throw new InvalidExternalHttpSettingsException();
        }
        expression.append(Pattern.quote(suffix));
        return Pattern.compile(expression.toString());
    }

    enum Kind {
        GET_JSON("GET"), POST_JSON("POST"), POST_FORM("POST");

        private final String method;

        Kind(String method) {
            this.method = method;
        }
    }
}
