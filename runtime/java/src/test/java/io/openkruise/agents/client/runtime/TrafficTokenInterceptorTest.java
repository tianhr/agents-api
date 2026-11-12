package io.openkruise.agents.client.runtime;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.junit.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.fail;

/**
 * Behavior tests for {@link TrafficTokenInterceptor}, the OkHttp application
 * interceptor that attaches the sandbox traffic access token to data-plane
 * requests. A local in-process {@link HttpServer} records the header the server
 * actually receives, locking in the three contract points:
 * <ul>
 *   <li>a non-empty token is injected as {@code e2b-traffic-access-token}</li>
 *   <li>an empty or {@code null} token sends no header (legacy behavior for
 *       sandboxes that are not JWT-protected)</li>
 *   <li>a provider that throws fails the call closed: the request never reaches
 *       the server</li>
 * </ul>
 *
 * <p>This file is mirrored byte-for-byte between {@code runtime/java} and
 * {@code e2b/java} (same rule as {@code CommandsTest}).
 */
public class TrafficTokenInterceptorTest {

    @Test
    public void injectsHeaderWhenTokenPresent() throws Exception {
        AtomicReference<String> seen = new AtomicReference<>();
        AtomicInteger calls = new AtomicInteger();
        HttpServer server = startServer(exchange -> {
            calls.incrementAndGet();
            seen.set(exchange.getRequestHeaders().getFirst(TrafficTokenInterceptor.TRAFFIC_TOKEN_HEADER));
            exchange.getRequestBody().close();
            respond(exchange, 200, "ok");
        });
        try {
            OkHttpClient client = clientWith(() -> "token-abc");
            try (Response response = client.newCall(getRequest(server)).execute()) {
                assertEquals(200, response.code());
            }
            assertEquals("token-abc", seen.get());
            assertEquals(1, calls.get());
        } finally {
            server.stop(0);
        }
    }

    @Test
    public void omitsHeaderWhenTokenEmpty() throws Exception {
        AtomicReference<String> seen = new AtomicReference<>("sentinel");
        HttpServer server = startServer(exchange -> {
            seen.set(exchange.getRequestHeaders().getFirst(TrafficTokenInterceptor.TRAFFIC_TOKEN_HEADER));
            exchange.getRequestBody().close();
            respond(exchange, 200, "ok");
        });
        try {
            OkHttpClient client = clientWith(() -> "");
            try (Response response = client.newCall(getRequest(server)).execute()) {
                assertEquals(200, response.code());
            }
            assertNull("empty token should send no traffic header", seen.get());
        } finally {
            server.stop(0);
        }
    }

    @Test
    public void omitsHeaderWhenTokenNull() throws Exception {
        AtomicReference<String> seen = new AtomicReference<>("sentinel");
        HttpServer server = startServer(exchange -> {
            seen.set(exchange.getRequestHeaders().getFirst(TrafficTokenInterceptor.TRAFFIC_TOKEN_HEADER));
            exchange.getRequestBody().close();
            respond(exchange, 200, "ok");
        });
        try {
            OkHttpClient client = clientWith(() -> null);
            try (Response response = client.newCall(getRequest(server)).execute()) {
                assertEquals(200, response.code());
            }
            assertNull("null token should send no traffic header", seen.get());
        } finally {
            server.stop(0);
        }
    }

    @Test
    public void failsClosedWhenProviderThrows() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        HttpServer server = startServer(exchange -> {
            calls.incrementAndGet();
            exchange.getRequestBody().close();
            respond(exchange, 200, "ok");
        });
        try {
            IOException boom = new IOException("traffic access token expired");
            OkHttpClient client = clientWith(() -> {
                throw boom;
            });
            try {
                client.newCall(getRequest(server)).execute();
                fail("call should fail closed when the provider throws");
            } catch (IOException e) {
                assertSame("the provider's IOException should propagate unwrapped", boom, e);
            }
            assertEquals("the request must never reach the server", 0, calls.get());
        } finally {
            server.stop(0);
        }
    }

    // --- helpers ---

    private static OkHttpClient clientWith(TrafficTokenProvider provider) {
        return new OkHttpClient.Builder()
            .addInterceptor(new TrafficTokenInterceptor(provider))
            .build();
    }

    private static Request getRequest(HttpServer server) {
        return new Request.Builder().url(baseUrl(server) + "/").get().build();
    }

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

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(status, bytes.length);
        OutputStream out = exchange.getResponseBody();
        out.write(bytes);
        out.close();
    }
}
