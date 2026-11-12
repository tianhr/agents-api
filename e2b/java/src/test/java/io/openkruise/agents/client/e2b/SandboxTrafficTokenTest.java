package io.openkruise.agents.client.e2b;

import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.openkruise.agents.client.runtime.TrafficTokenInterceptor;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.junit.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayDeque;
import java.util.Base64;
import java.util.Queue;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

/**
 * Sandbox-level tests for Traffic JWT wiring: manager seeding (create/connect),
 * lazy bootstrap from {@code enable-jwt-auth} metadata, legacy fallback for
 * non-JWT tokens, and data-plane header injection through the shared OkHttp
 * client. Two in-process {@link HttpServer}s mock the management API (refresh +
 * lifecycle) and the envd data plane (records the traffic header), mirroring the
 * Go SDK's {@code refreshEndpointSetup} / {@code seedSetup} suites.
 *
 * <p>The Go {@code WithTrafficAccessToken} explicit-seed cases have no Java
 * counterpart (the SDK has no functional-options pattern), so seeding is
 * exercised through the create/connect response token and the metadata probe
 * instead -- the two seed entry points Java actually exposes.
 */
public class SandboxTrafficTokenTest {

    // --- data-plane header injection ---

    @Test
    public void dataPlaneInjectsTrafficHeaderAfterBootstrap() throws Exception {
        double now = System.currentTimeMillis() / 1000.0;
        String first = tokenWithValidity(now, 3600);
        String second = tokenWithValidity(now + 3599, 3600);

        ManagementMock mgmt = new ManagementMock();
        mgmt.queueRefresh(first);
        mgmt.queueRefresh(second);
        DataPlaneMock dataPlane = new DataPlaneMock();
        try {
            ConnectionConfig config = new ConnectionConfig.Builder()
                .domain("unused")
                .apiKey("test-key")
                .apiURL(mgmt.baseUrl())
                .build();
            Sandbox sandbox = new Sandbox("sbx-1", "envd-token", config);
            try {
                OkHttpClient client = sandbox.getRuntimeClient().getConfig().getOrCreateHttpClient();

                // Without a manager the data-plane request carries no traffic header.
                get(client, dataPlane.baseUrl() + "/");
                assertNull("no manager should send no traffic header", dataPlane.lastHeader.get());

                // Installing an empty-seed manager bootstraps on the next request.
                sandbox.installTrafficTokenManager("");
                get(client, dataPlane.baseUrl() + "/");
                assertEquals(first, dataPlane.lastHeader.get());
                assertEquals(1, mgmt.refreshCalls.get());

                // A forced refresh swaps the token for subsequent requests.
                assertEquals(second, sandbox.refreshTrafficAccessToken());
                get(client, dataPlane.baseUrl() + "/");
                assertEquals(second, dataPlane.lastHeader.get());

                // The cached token is exposed for diagnostics.
                assertEquals(second, sandbox.getTrafficAccessToken());
            } finally {
                sandbox.close();
            }
        } finally {
            mgmt.close();
            dataPlane.close();
        }
    }

    @Test
    public void providerWithoutManagerSendsNoHeader() throws Exception {
        DataPlaneMock dataPlane = new DataPlaneMock();
        try {
            ConnectionConfig config = new ConnectionConfig.Builder()
                .domain("unused")
                .apiKey("test-key")
                .build();
            Sandbox sandbox = new Sandbox("sbx-1", "envd-token", config);
            try {
                OkHttpClient client = sandbox.getRuntimeClient().getConfig().getOrCreateHttpClient();
                get(client, dataPlane.baseUrl() + "/");
                assertNull("provider without a manager should send no header", dataPlane.lastHeader.get());
                assertEquals("", sandbox.getTrafficAccessToken());
            } finally {
                sandbox.close();
            }
        } finally {
            dataPlane.close();
        }
    }

    @Test
    public void nonJwtTokenKeepsLegacyBehavior() throws Exception {
        ConnectionConfig config = new ConnectionConfig.Builder().domain("unused").build();
        Sandbox sandbox = new Sandbox("sbx-1", "envd-token", config);
        try {
            // Legacy opaque tokens are rejected at install time: no manager, no refresh.
            sandbox.installTrafficTokenManager("5b14a58f-93f4-4d3e-9a92-2f3e0e1a9e33");
            assertEquals("", sandbox.getTrafficAccessToken());
            try {
                sandbox.refreshTrafficAccessToken();
                fail("refreshTrafficAccessToken should fail without a manager");
            } catch (TrafficAccessTokenException expected) {
                // wanted
            }
        } finally {
            sandbox.close();
        }
    }

    // --- create/connect seeding ---

    @Test
    public void createSeedsTrafficTokenFromResponse() throws Exception {
        double now = System.currentTimeMillis() / 1000.0;
        String seed = tokenWithValidity(now, 3600);

        ManagementMock mgmt = new ManagementMock();
        mgmt.sandboxResponseJson = sandboxResponse("sbx-1", "envd-token", seed);
        try {
            ConnectionConfig config = new ConnectionConfig.Builder()
                .domain("unused")
                .apiKey("test-key")
                .apiURL(mgmt.baseUrl())
                .build();
            SandboxApi api = new SandboxApi(config);
            Sandbox sandbox = api.create("code-interpreter");
            try {
                assertEquals(1, mgmt.createCalls.get());
                assertEquals("create should seed the manager with the response JWT",
                    seed, sandbox.getTrafficAccessToken());
                assertEquals("a seeded manager refreshes lazily", 0, mgmt.refreshCalls.get());
            } finally {
                sandbox.close();
            }
        } finally {
            mgmt.close();
        }
    }

    @Test
    public void connectLazyBootstrapsFromJwtMetadata() throws Exception {
        double now = System.currentTimeMillis() / 1000.0;
        String fresh = tokenWithValidity(now, 3600);

        ManagementMock mgmt = new ManagementMock();
        // Connect carries no token; the metadata probe must resume JWT handling.
        mgmt.sandboxResponseJson = sandboxResponse("sbx-1", "envd-token", "");
        mgmt.detailJson = sandboxDetail("sbx-1", true);
        mgmt.queueRefresh(fresh);
        try {
            ConnectionConfig config = new ConnectionConfig.Builder()
                .domain("unused")
                .apiKey("test-key")
                .apiURL(mgmt.baseUrl())
                .build();
            SandboxApi api = new SandboxApi(config);
            Sandbox sandbox = api.connect("sbx-1");
            try {
                assertEquals(1, mgmt.connectCalls.get());
                assertEquals("the metadata probe should have run", 1, mgmt.infoCalls.get());
                assertEquals("a lazy manager has no cached token yet", "", sandbox.getTrafficAccessToken());
                // The lazily installed manager bootstraps on demand.
                assertEquals(fresh, sandbox.refreshTrafficAccessToken());
                assertEquals(1, mgmt.refreshCalls.get());
            } finally {
                sandbox.close();
            }
        } finally {
            mgmt.close();
        }
    }

    @Test
    public void connectLegacyTokenInstallsNoManager() throws Exception {
        ManagementMock mgmt = new ManagementMock();
        mgmt.sandboxResponseJson = sandboxResponse("sbx-1", "envd-token", "opaque-uuid-style-token");
        try {
            ConnectionConfig config = new ConnectionConfig.Builder()
                .domain("unused")
                .apiKey("test-key")
                .apiURL(mgmt.baseUrl())
                .build();
            SandboxApi api = new SandboxApi(config);
            Sandbox sandbox = api.connect("sbx-1");
            try {
                assertEquals("a legacy response token installs no manager", "", sandbox.getTrafficAccessToken());
                assertEquals("a non-empty token must not trigger a metadata probe", 0, mgmt.infoCalls.get());
                try {
                    sandbox.refreshTrafficAccessToken();
                    fail("refreshTrafficAccessToken should fail without a manager");
                } catch (TrafficAccessTokenException expected) {
                    // wanted
                }
            } finally {
                sandbox.close();
            }
        } finally {
            mgmt.close();
        }
    }

    // --- mock management API (create / connect / getInfo / refresh) ---

    private static final class ManagementMock implements AutoCloseable {
        final HttpServer server;
        final AtomicInteger refreshCalls = new AtomicInteger();
        final AtomicInteger createCalls = new AtomicInteger();
        final AtomicInteger connectCalls = new AtomicInteger();
        final AtomicInteger infoCalls = new AtomicInteger();
        final Queue<String> refreshTokens = new ArrayDeque<>();
        volatile String sandboxResponseJson = "{}";
        volatile String detailJson; // null -> getInfo answers 404

        ManagementMock() throws IOException {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/", this::handle);
            server.setExecutor(Executors.newCachedThreadPool());
            server.start();
        }

        String baseUrl() {
            return "http://127.0.0.1:" + server.getAddress().getPort();
        }

        void queueRefresh(String token) {
            refreshTokens.add(token);
        }

        private void handle(HttpExchange exchange) throws IOException {
            String path = exchange.getRequestURI().getPath();
            String method = exchange.getRequestMethod();
            exchange.getRequestBody().close();
            if ("POST".equals(method) && path.endsWith("/traffic-access-token")) {
                refreshCalls.incrementAndGet();
                String token = refreshTokens.poll();
                if (token == null) {
                    exchange.getResponseHeaders().set("Retry-After", "60");
                    respondJson(exchange, 429, "{}");
                } else {
                    respondJson(exchange, 200, refreshBody(token));
                }
            } else if ("POST".equals(method) && path.endsWith("/connect")) {
                connectCalls.incrementAndGet();
                respondJson(exchange, 200, sandboxResponseJson);
            } else if ("POST".equals(method) && path.endsWith("/sandboxes")) {
                createCalls.incrementAndGet();
                respondJson(exchange, 200, sandboxResponseJson);
            } else if ("GET".equals(method) && path.startsWith("/sandboxes/")) {
                infoCalls.incrementAndGet();
                if (detailJson != null) {
                    respondJson(exchange, 200, detailJson);
                } else {
                    respondJson(exchange, 404, "{\"error\":\"not found\"}");
                }
            } else {
                respondJson(exchange, 404, "{\"error\":\"not found\"}");
            }
        }

        @Override
        public void close() {
            server.stop(0);
        }
    }

    // --- mock envd data plane (records the traffic header) ---

    private static final class DataPlaneMock implements AutoCloseable {
        final HttpServer server;
        final AtomicReference<String> lastHeader = new AtomicReference<>();
        final AtomicInteger calls = new AtomicInteger();

        DataPlaneMock() throws IOException {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/", exchange -> {
                calls.incrementAndGet();
                lastHeader.set(exchange.getRequestHeaders()
                    .getFirst(TrafficTokenInterceptor.TRAFFIC_TOKEN_HEADER));
                exchange.getRequestBody().close();
                respondJson(exchange, 200, "ok");
            });
            server.setExecutor(Executors.newCachedThreadPool());
            server.start();
        }

        String baseUrl() {
            return "http://127.0.0.1:" + server.getAddress().getPort();
        }

        @Override
        public void close() {
            server.stop(0);
        }
    }

    // --- HTTP / JSON helpers ---

    private static void get(OkHttpClient client, String url) throws IOException {
        Request request = new Request.Builder().url(url).get().build();
        try (Response response = client.newCall(request).execute()) {
            if (response.body() != null) {
                response.body().bytes(); // drain
            }
        }
    }

    private static void respondJson(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        OutputStream out = exchange.getResponseBody();
        out.write(bytes);
        out.close();
    }

    private static String sandboxResponse(String sandboxID, String envdAccessToken, String trafficAccessToken) {
        return "{\"templateID\":\"code-interpreter\""
            + ",\"sandboxID\":\"" + sandboxID + "\""
            + ",\"clientID\":\"\""
            + ",\"envdVersion\":\"0.0.1\""
            + ",\"envdAccessToken\":\"" + envdAccessToken + "\""
            + ",\"trafficAccessToken\":\"" + trafficAccessToken + "\""
            + ",\"domain\":\"example.com\"}";
    }

    // SandboxDetail is an OpenAPI-generated model whose validateJsonObject()
    // rejects a payload missing any required field, so the mock must include the
    // full required set (templateID/sandboxID/clientID/startedAt/endAt/
    // envdVersion/cpuCount/memoryMB/diskSizeMB/state), not just the metadata.
    private static String sandboxDetail(String sandboxID, boolean jwtAuth) {
        return "{\"templateID\":\"code-interpreter\""
            + ",\"sandboxID\":\"" + sandboxID + "\""
            + ",\"clientID\":\"\""
            + ",\"startedAt\":\"2024-01-01T00:00:00Z\""
            + ",\"endAt\":\"2024-01-01T01:00:00Z\""
            + ",\"envdVersion\":\"0.0.1\""
            + ",\"envdAccessToken\":\"envd-token\""
            + ",\"domain\":\"example.com\""
            + ",\"cpuCount\":2"
            + ",\"memoryMB\":512"
            + ",\"diskSizeMB\":1024"
            + ",\"state\":\"running\""
            + ",\"metadata\":{\"" + TrafficTokenManager.JWT_AUTH_METADATA_KEY + "\":\"" + (jwtAuth ? "true" : "false") + "\"}}";
    }

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
