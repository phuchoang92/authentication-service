package com.vpbank.dcp.infrastructure.adapter.out.http;

import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** An external JSON endpoint and its exact response contract. */
public final class ExternalEndpoint<S, E> {

    private static final Pattern VARIABLE = Pattern.compile("\\{([A-Za-z][A-Za-z0-9]*)\\}");
    private static final String ENCODED_SEGMENT = "(?:[A-Za-z0-9._~-]|%[0-9A-F]{2})+";

    private final Kind kind;
    private final String template;
    private final String path;
    private final Class<S> successType;
    private final Class<E> errorType;
    private final Set<Integer> successStatuses;
    private final Set<Integer> errorStatuses;

    private ExternalEndpoint(Kind kind, String template, String path, Class<S> successType,
                             Set<Integer> successStatuses, Class<E> errorType,
                             Set<Integer> errorStatuses) {
        this.kind = kind;
        this.template = template;
        this.path = path;
        this.successType = Objects.requireNonNull(successType, "successType");
        this.errorType = Objects.requireNonNull(errorType, "errorType");
        this.successStatuses = Set.copyOf(successStatuses);
        this.errorStatuses = Set.copyOf(errorStatuses);
        if (!template.startsWith("/") || template.contains("//") || template.contains("?")
                || template.contains("#") || template.contains("%") || template.contains("\\")
                || this.successStatuses.isEmpty()
                || this.successStatuses.stream().anyMatch(status -> status < 200 || status > 299)
                || this.errorStatuses.stream().anyMatch(status -> status < 400 || status > 599)
                || !Collections.disjoint(this.successStatuses, this.errorStatuses)
                || (this.errorStatuses.isEmpty() != (errorType == Void.class))) {
            throw new InvalidExternalHttpSettingsException();
        }
        routePattern(template);
    }

    public static <S> ExternalEndpoint<S, Void> getJson(String path, Class<S> successType,
                                                        Set<Integer> successStatuses) {
        return getJson(path, successType, successStatuses, Void.class, Set.of());
    }

    public static <S, E> ExternalEndpoint<S, E> getJson(String path, Class<S> successType,
                                                        Set<Integer> successStatuses,
                                                        Class<E> errorType, Set<Integer> errorStatuses) {
        return new ExternalEndpoint<>(Kind.GET_JSON, path, path, successType, successStatuses,
                errorType, errorStatuses);
    }

    public static <S> ExternalEndpoint<S, Void> postJson(String path, Class<S> successType,
                                                         Set<Integer> successStatuses) {
        return postJson(path, successType, successStatuses, Void.class, Set.of());
    }

    public static <S, E> ExternalEndpoint<S, E> postJson(String path, Class<S> successType,
                                                         Set<Integer> successStatuses,
                                                         Class<E> errorType, Set<Integer> errorStatuses) {
        return new ExternalEndpoint<>(Kind.POST_JSON, path, path, successType, successStatuses,
                errorType, errorStatuses);
    }

    public static <S, E> ExternalEndpoint<S, E> postForm(String path, Class<S> successType,
                                                         Set<Integer> successStatuses,
                                                         Class<E> errorType, Set<Integer> errorStatuses) {
        return new ExternalEndpoint<>(Kind.POST_FORM, path, path, successType, successStatuses,
                errorType, errorStatuses);
    }

    public ExternalEndpoint<S, E> bindSegment(String name, String value) {
        Objects.requireNonNull(name, "name");
        String placeholder = "{" + name + "}";
        if (!template.contains(placeholder) || !path.contains(placeholder)) {
            throw new InvalidExternalHttpSettingsException();
        }
        return new ExternalEndpoint<>(kind, template,
                path.replace(placeholder, ExternalPath.segment(value)), successType,
                successStatuses, errorType, errorStatuses);
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

    Class<S> successType() {
        return successType;
    }

    Class<E> errorType() {
        return errorType;
    }

    boolean acceptsSuccess(int status) {
        return successStatuses.contains(status);
    }

    boolean acceptsError(int status) {
        return errorStatuses.contains(status);
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
