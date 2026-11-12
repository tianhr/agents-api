package io.openkruise.agents.client.e2b;

import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.junit.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Endpoint tests for {@link TrafficTokenRefresher}, using a local in-process
 * {@link HttpServer} to mock the management API (the JDK-server counterpart of
 * the Go SDK's {@code httptest} suites). They lock in the refresh wire contract:
 * <ul>
 *   <li>{@code POST {base}/sandboxes/{id}/traffic-access-token} with the sandbox
 *       ID percent-escaped into a single path segment</li>
 *   <li>{@code X-API-Key} authentication, applied last so it wins over a
 *       same-named custom connection header</li>
 *   <li>non-2xx surfaces a {@link TrafficAccessTokenRefreshException} carrying
 *       the status and Retry-After delay, without leaking the response body</li>
 *   <li>the base is the constant {@code /kruise/api} prefix across routing
 *       protocols (the endpoint's only registered form upstream), while an
 *       explicit {@code apiURL} override wins as-is with a trailing slash trimmed</li>
 * </ul>
 */
public class TrafficTokenRefreshEndpointTest {

    @Test
    public void refreshTrafficAccessToken() throws Exception {
        double now = System.currentTimeMillis() / 1000.0;
        String token = tokenWithValidity(now, 3600);
        String body = refreshBody(token);
        Recording recording = new Recording();

        HttpServer server = startServer(exchange -> {
            recording.record(exchange);
            respondJson(exchange, 200, body);
        });
        try {
            ConnectionConfig config = new ConnectionConfig.Builder()
                .domain("unused")
                .apiKey("test-key")
                .apiURL(baseUrl(server))
                .build();

            TrafficAccessToken got = TrafficTokenRefresher.refresh(config, "sbx-1");
            assertEquals(token, got.getToken());
            assertEquals("POST", recording.method.get());
            assertTrue("refresh path should end with /traffic-access-token",
                recording.rawPath.get().endsWith("/traffic-access-token"));
            assertEquals("test-key", recording.apiKey.get());

            // Sandbox IDs are percent-escaped into a single path segment.
            TrafficTokenRefresher.refresh(config, "sbx/needs-escaping");
            assertTrue("escaped sandbox ID should ride in the raw path, got " + recording.rawPath.get(),
                recording.rawPath.get().contains("sbx%2Fneeds-escaping"));
        } finally {
            server.stop(0);
        }
    }

    @Test
    public void refreshTrafficAccessTokenError() throws Exception {
        HttpServer server = startServer(exchange -> {
            exchange.getRequestBody().close();
            exchange.getResponseHeaders().set("Retry-After", "60");
            // The body carries a unique marker that must never reach the error.
            respondJson(exchange, 429, "{\"error\":\"secret-detail\"}");
        });
        try {
            ConnectionConfig config = new ConnectionConfig.Builder()
                .domain("unused")
                .apiKey("test-key")
                .apiURL(baseUrl(server))
                .build();

            try {
                TrafficTokenRefresher.refresh(config, "sbx-1");
                fail("want TrafficAccessTokenRefreshException on 429");
            } catch (TrafficAccessTokenRefreshException e) {
                assertEquals(429, e.getStatusCode());
                assertEquals(60.0, e.getRetryAfterSeconds(), 0.0);
                assertFalse("error must not embed the response body: " + e.getMessage(),
                    e.getMessage().contains("secret-detail"));
            }
        } finally {
            server.stop(0);
        }
    }

    @Test
    public void refreshTrafficAccessTokenCustomHeaders() throws Exception {
        double now = System.currentTimeMillis() / 1000.0;
        String body = refreshBody(tokenWithValidity(now, 3600));
        Recording recording = new Recording();

        HttpServer server = startServer(exchange -> {
            recording.record(exchange);
            respondJson(exchange, 200, body);
        });
        try {
            ConnectionConfig config = new ConnectionConfig.Builder()
                .domain("unused")
                .apiKey("test-key")
                .apiURL(baseUrl(server))
                .addHeader("X-Custom-Header", "custom-value")
                // A custom X-API-Key must be shadowed by the configured API key.
                .addHeader("X-API-Key", "shadowed")
                .build();

            TrafficTokenRefresher.refresh(config, "sbx-1");
            assertEquals("custom-value", recording.customHeader.get());
            assertEquals("X-API-Key should win over the shadowed custom header",
                "test-key", recording.apiKey.get());
        } finally {
            server.stop(0);
        }
    }

    /**
     * Pins the refresh URL to the upstream's single registered form: the
     * endpoint exists only under the {@code /kruise/api} prefix, so both routing
     * protocols must target {@code {scheme}://{domain}/kruise/api/sandboxes/{id}/
     * traffic-access-token} (a native {@code https://api.<domain>} base would
     * 404), while an explicit {@code apiURL} override still wins as-is.
     */
    @Test
    public void refreshTrafficAccessTokenURL() throws Exception {
        List<String> paths = Collections.synchronizedList(new ArrayList<String>());
        HttpServer server = startServer(exchange -> {
            exchange.getRequestBody().close();
            paths.add(exchange.getRequestURI().getPath());
            // The stub response fails validation; only the requested path matters.
            respondJson(exchange, 200, "{\"trafficAccessToken\":\"\",\"trafficAccessTokenExpiration\":\"\"}");
        });
        try {
            String host = baseUrl(server).substring("http://".length());

            assertRefreshPath(paths, host, null, null,
                "/kruise/api/sandboxes/sbx-1/traffic-access-token");
            assertRefreshPath(paths, host, ConnectionConfig.Protocol.PRIVATE, null,
                "/kruise/api/sandboxes/sbx-1/traffic-access-token");
            assertRefreshPath(paths, host, null, baseUrl(server) + "/custom/base",
                "/custom/base/sandboxes/sbx-1/traffic-access-token");
            assertRefreshPath(paths, host, null, baseUrl(server) + "/custom/base/",
                "/custom/base/sandboxes/sbx-1/traffic-access-token");
        } finally {
            server.stop(0);
        }
    }

    private void assertRefreshPath(List<String> paths, String host, ConnectionConfig.Protocol protocol,
        String apiURL, String want) throws Exception {
        paths.clear();
        ConnectionConfig.Builder builder = new ConnectionConfig.Builder()
            .domain(host)
            .scheme("http")
            .apiKey("test-key");
        if (protocol != null) {
            builder.protocol(protocol);
        }
        if (apiURL != null) {
            builder.apiURL(apiURL);
        }
        try {
            TrafficTokenRefresher.refresh(builder.build(), "sbx-1");
        } catch (TrafficAccessTokenException ignored) {
            // The stub response is intentionally invalid; the path is the subject.
        }
        assertEquals("exactly one refresh call", 1, paths.size());
        assertEquals(want, paths.get(0));
    }

    // --- mock server helpers ---

    private static HttpServer startServer(HttpHandler handler) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", handler);
        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
        return server;
    }

    private static String baseUrl(HttpServer server) {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    private static void respondJson(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        OutputStream out = exchange.getResponseBody();
        out.write(bytes);
        out.close();
    }

    /** Captures what the mock server saw on the most recent request. */
    private static final class Recording {
        final AtomicReference<String> method = new AtomicReference<>();
        final AtomicReference<String> rawPath = new AtomicReference<>();
        final AtomicReference<String> apiKey = new AtomicReference<>();
        final AtomicReference<String> customHeader = new AtomicReference<>();
        final AtomicInteger calls = new AtomicInteger();

        void record(HttpExchange exchange) throws IOException {
            exchange.getRequestBody().close();
            method.set(exchange.getRequestMethod());
            rawPath.set(exchange.getRequestURI().getRawPath());
            apiKey.set(exchange.getRequestHeaders().getFirst("X-API-Key"));
            customHeader.set(exchange.getRequestHeaders().getFirst("X-Custom-Header"));
            calls.incrementAndGet();
        }
    }

    // --- test JWT helpers (mirror TrafficTokenManagerTest) ---

    private static String refreshBody(String token) throws TrafficAccessTokenException {
        return "{\"trafficAccessToken\":\"" + token
            + "\",\"trafficAccessTokenExpiration\":\"" + rfc3339(jwtExp(token)) + "\"}";
    }

    private static String rfc3339(double epochSeconds) {
        return OffsetDateTime.ofInstant(Instant.ofEpochSecond(Math.round(epochSeconds)), ZoneOffset.UTC)
            .format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);
    }

    private static String signTestJwt(JsonObject claims) {
        String encoded = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(claims.toString().getBytes(StandardCharsets.UTF_8));
        return "header." + encoded + ".signature";
    }

    private static String tokenWithValidity(double now, double validity) {
        JsonObject claims = new JsonObject();
        claims.addProperty("exp", now + validity);
        claims.addProperty("iat", now);
        return signTestJwt(claims);
    }

    private static double jwtExp(String token) throws TrafficAccessTokenException {
        return TrafficTokenManager.parseTrafficJwtExpiration(token).expiresAt;
    }
}
