package com.harness.llm;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.internal.MontoyaObjectFactory;
import burp.api.montoya.internal.ObjectFactoryLocator;
import burp.api.montoya.logging.Logging;
import com.harness.llm.model.AnalysisModels.TestPlan;
import com.harness.llm.model.AnalysisModels.ValidationSubmission;

import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.BiFunction;
import java.util.function.Function;

/**
 * In-memory Montoya fakes for driving ValidationExecutor.execute() end to end
 * (capability dispatch, fingerprint check, executor, Logic class, submission)
 * without Burp or a network. Ported from the code review 02 javac checks
 * (reviews/2026-10-17-code-review-02/java/ExecutorChecks.java): every request
 * the executor sends is recorded, and a test-supplied responder answers it.
 * Any Montoya method the fakes do not model throws, so an executor that starts
 * depending on more of the API fails loudly instead of reading a null.
 */
final class FakeMontoya {
    static final String ORIGIN = "https://shop.example";

    private FakeMontoya() {}

    record Reply(int status, String body, Map<String, String> headers) {
        static Reply of(int status, String body) { return new Reply(status, body, Map.of()); }
    }

    /** One completed execute() call: the single submission, the panel outcome and every request sent. */
    record Run(ValidationSubmission submission, String outcome, String outcomeDetail, List<HttpRequest> sent) {
        boolean confirmed() { return submission.confirmed; }
        String status() { return submission.status; }
    }

    @SuppressWarnings("unchecked")
    static <T> T proxy(Class<T> type, BiFunction<String, Object[], Object> answer) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, (self, method, args) -> {
            switch (method.getName()) {
                case "equals": return self == args[0];
                case "hashCode": return System.identityHashCode(self);
                case "toString": if (args == null) return type.getSimpleName() + "@" + System.identityHashCode(self);
                default: return answer.apply(method.getName(), args == null ? new Object[0] : args);
            }
        });
    }

    static HttpHeader header(String name, String value) {
        return proxy(HttpHeader.class, (m, a) -> switch (m) {
            case "name" -> name;
            case "value" -> value;
            default -> throw new UnsupportedOperationException("HttpHeader." + m);
        });
    }

    static HttpParameter parameter(String name, String value, HttpParameterType type) {
        return proxy(ParsedHttpParameter.class, (m, a) -> switch (m) {
            case "name" -> name;
            case "value" -> value;
            case "type" -> type;
            default -> throw new UnsupportedOperationException("HttpParameter." + m);
        });
    }

    /**
     * Burp installs Montoya's static object factory at runtime; the executor
     * builds probe parameters through HttpParameter.parameter(...), which
     * reads it. Returns the previous factory so a test can restore it.
     */
    static MontoyaObjectFactory installParameterFactory() {
        MontoyaObjectFactory previous = ObjectFactoryLocator.FACTORY;
        ObjectFactoryLocator.FACTORY = proxy(MontoyaObjectFactory.class, (m, a) -> {
            if (m.equals("parameter")) return parameter((String) a[0], (String) a[1], (HttpParameterType) a[2]);
            throw new UnsupportedOperationException("MontoyaObjectFactory." + m);
        });
        return previous;
    }

    static Map<String, String> headers(String... nameValuePairs) {
        Map<String, String> h = new LinkedHashMap<>();
        for (int i = 0; i < nameValuePairs.length; i += 2) h.put(nameValuePairs[i], nameValuePairs[i + 1]);
        return h;
    }

    static HttpRequest request(String method, String path, String body, Map<String, String> headers) {
        return request(method, path, body, headers, Map.of());
    }

    /** An immutable request; the with* methods return modified copies, as Montoya's do. */
    static HttpRequest request(String method, String path, String body, Map<String, String> headers,
                               Map<String, String> urlParams) {
        Map<String, String> h = new LinkedHashMap<>(headers);
        Map<String, String> p = new LinkedHashMap<>(urlParams);
        return proxy(HttpRequest.class, (m, a) -> switch (m) {
            case "method" -> method;
            case "path" -> path;
            case "url" -> ORIGIN + path;
            case "bodyToString" -> body;
            case "isInScope" -> true;
            case "headers" -> h.entrySet().stream().map(e -> header(e.getKey(), e.getValue())).toList();
            case "parameters" -> p.entrySet().stream()
                    .map(e -> (ParsedHttpParameter) parameter(e.getKey(), e.getValue(), HttpParameterType.URL)).toList();
            case "withMethod" -> request((String) a[0], path, body, h, p);
            case "withPath" -> request(method, (String) a[0], body, h, p);
            case "withBody" -> request(method, path, (String) a[0], h, p);
            case "withParameter" -> {
                HttpParameter hp = (HttpParameter) a[0];
                Map<String, String> np = new LinkedHashMap<>(p);
                np.put(hp.name(), hp.value());
                yield request(method, path, body, h, np);
            }
            case "withRemovedHeader" -> {
                Map<String, String> nh = new LinkedHashMap<>(h);
                nh.keySet().removeIf(k -> k.equalsIgnoreCase((String) a[0]));
                yield request(method, path, body, nh, p);
            }
            case "withUpdatedHeader", "withAddedHeader" -> {
                Map<String, String> nh = new LinkedHashMap<>(h);
                nh.keySet().removeIf(k -> k.equalsIgnoreCase((String) a[0]));
                nh.put((String) a[0], (String) a[1]);
                yield request(method, path, body, nh, p);
            }
            default -> throw new UnsupportedOperationException("HttpRequest." + m);
        });
    }

    static String headerOf(HttpRequest request, String name) {
        for (HttpHeader h : request.headers()) if (h.name().equalsIgnoreCase(name)) return h.value();
        return null;
    }

    static String paramOf(HttpRequest request, String name) {
        for (var p : request.parameters()) if (p.name().equals(name)) return p.value();
        return null;
    }

    static HttpRequestResponse exchange(HttpRequest request, Reply reply) {
        HttpResponse response = reply == null ? null : response(reply);
        return proxy(HttpRequestResponse.class, (m, a) -> switch (m) {
            case "request" -> request;
            case "response" -> response;
            default -> throw new UnsupportedOperationException("HttpRequestResponse." + m);
        });
    }

    private static HttpResponse response(Reply reply) {
        Map<String, String> h = reply.headers();
        return proxy(HttpResponse.class, (m, a) -> switch (m) {
            case "statusCode" -> (short) reply.status();
            case "bodyToString" -> reply.body();
            case "headerValue" -> {
                String wanted = ((String) a[0]).toLowerCase(Locale.ROOT);
                String found = null;
                for (var e : h.entrySet()) if (e.getKey().toLowerCase(Locale.ROOT).equals(wanted)) { found = e.getValue(); break; }
                yield found;
            }
            case "hasHeader" -> h.keySet().stream().anyMatch(k -> k.equalsIgnoreCase((String) a[0]));
            case "headers" -> h.entrySet().stream().map(e -> header(e.getKey(), e.getValue())).toList();
            default -> throw new UnsupportedOperationException("HttpResponse." + m);
        });
    }

    /**
     * Runs one plan through the public ValidationExecutor.execute() path and
     * waits for its completion callback.
     */
    static Run execute(String capability, HttpRequest request, Reply capturedReply,
                       Function<HttpRequest, Reply> responder) throws Exception {
        List<HttpRequest> sent = new CopyOnWriteArrayList<>();
        List<ValidationSubmission> submissions = new CopyOnWriteArrayList<>();
        Http http = proxy(Http.class, (m, a) -> {
            if (!m.equals("sendRequest") || a.length != 1) throw new UnsupportedOperationException("Http." + m);
            HttpRequest r = (HttpRequest) a[0];
            sent.add(r);
            return exchange(r, responder.apply(r));
        });
        Logging logging = proxy(Logging.class, (m, a) -> null);
        MontoyaApi api = proxy(MontoyaApi.class, (m, a) -> switch (m) {
            case "http" -> http;
            case "logging" -> logging;
            default -> throw new UnsupportedOperationException("MontoyaApi." + m);
        });
        HarnessClient client = new HarnessClient("http://127.0.0.1:8000", 1) {
            @Override public void submitValidationResult(ValidationSubmission submission) { submissions.add(submission); }
        };
        ValidationExecutor executor = new ValidationExecutor(api, client);
        HttpRequestResponse source = exchange(request, capturedReply);
        TestPlan plan = new TestPlan();
        plan.id = "plan-" + capability;
        plan.capability = capability;
        plan.execution_plane = "burp";
        plan.source_exchange_hash = ValidationExecutor.exchangeFingerprint(source);
        executor.registerSources(source, List.of(plan));

        CountDownLatch done = new CountDownLatch(1);
        String[] outcome = new String[2];
        executor.execute(plan, (status, detail) -> { outcome[0] = status; outcome[1] = detail; done.countDown(); });
        if (!done.await(30, TimeUnit.SECONDS)) throw new AssertionError("executor did not complete within 30s");
        if (submissions.size() != 1) throw new AssertionError("expected one submission, got " + submissions.size());
        ValidationSubmission submission = submissions.get(0);
        if ("error".equals(submission.status)) throw new AssertionError("executor errored: " + submission.summary);
        return new Run(submission, outcome[0], outcome[1], new ArrayList<>(sent));
    }
}
