package io.openkruise.agents.client.examples;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import io.openkruise.agents.client.e2b.ConnectionConfig;
import io.openkruise.agents.client.e2b.Sandbox;
import io.openkruise.agents.client.e2b.SandboxApi;
import io.openkruise.agents.client.e2b.TrafficTokenManager;
import io.openkruise.agents.client.e2b.api.models.NewSandbox;
import io.openkruise.agents.client.runtime.codeinterpreter.Execution;
import io.openkruise.agents.client.runtime.commands.CommandResult;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

/**
 * End-to-end demo of Traffic JWT against a sandbox-gateway with
 * {@code enable-jwt-auth} -- the Java counterpart of the Python SDK's
 * {@code demo_jwt_gateway.py} and the Go {@code examples/jwt-gateway-example}.
 *
 * <p>Deployment prerequisites (same as the Python/Go demos):
 * <ol>
 *   <li>{@code jwt-e2e-oidc-provider} deployed in {@code sandbox-system},
 *       reachable in-cluster.</li>
 *   <li>sandbox-gateway upgraded with
 *       {@code gateway.envoy.pluginConfig.enableJwtAuth=true}, an OIDC
 *       {@code discoveryUrl} pointing at the provider, and the provider CA
 *       {@code caConfigMap}.</li>
 *   <li>{@code kubectl} on PATH with access to the sandbox resources.</li>
 * </ol>
 *
 * <p>Environment variables (defaults in parentheses):
 * <ul>
 *   <li>{@code E2B_DOMAIN} -- sandbox domain (required); the management API and
 *       the data plane are both derived from it.</li>
 *   <li>{@code E2B_API_KEY} -- management API key (optional).</li>
 *   <li>{@code E2B_PROTOCOL} -- routing protocol ({@code PRIVATE}).</li>
 *   <li>{@code E2B_API_URL} -- management API override (optional; defaults to
 *       {@code {scheme}://{E2B_DOMAIN}/kruise/api}).</li>
 *   <li>{@code SSL_CERT_FILE} -- when set, https is used and the PEM CA bundle
 *       is trusted (data plane and proxy upstream).</li>
 *   <li>{@code JWT_PROVIDER_SERVICE} ({@code jwt-e2e-oidc-provider}),
 *       {@code JWT_PROVIDER_NAMESPACE} ({@code sandbox-system}),
 *       {@code JWT_PROVIDER_FORWARD_PORT} ({@code 18080}),
 *       {@code JWT_TOKEN_VALIDITY_SECONDS} ({@code 65}).</li>
 * </ul>
 *
 * <p>Because the OSS sandbox-manager issues opaque UUID tokens, this demo
 * mirrors the upstream E2E suite: real JWTs are minted by the external provider
 * and driven through the SDK's native refresh path. Unlike the Python demo
 * (which monkey-patches the refresh function) and the Go demo (which seeds via
 * {@code WithTrafficAccessToken}), the Java SDK exposes exactly two seed entry
 * points -- the {@code trafficAccessToken} on a create/connect response and the
 * {@code enable-jwt-auth} metadata probe -- and has no explicit-seed option. So
 * this demo runs a local translating proxy that:
 * <ul>
 *   <li>rewrites the sandbox refresh endpoint
 *       ({@code POST /sandboxes/{id}/traffic-access-token}) into the provider's
 *       {@code /issue} call, exercising the full SDK refresh path (headers,
 *       Retry-After handling, response validation) end to end;</li>
 *   <li>injects a freshly issued JWT into the {@code trafficAccessToken} field
 *       of the create/connect responses forwarded from the real manager, which
 *       is how the SDK seeds its {@link TrafficTokenManager};</li>
 *   <li>reverse-proxies every other management request to the real manager.</li>
 * </ul>
 * The data plane is not proxied: it goes straight to the gateway
 * ({@code {scheme}://{domain}/kruise/{id}/{port}}) carrying the
 * {@code e2b-traffic-access-token} header the gateway validates.
 *
 * <p>Flow: create (JWT opt-in annotation) -> commands.run -> run_code ->
 * {@code getTrafficAccessToken()}/{@code refreshTrafficAccessToken()} ->
 * pause -> connect -> automatic-refresh watch -> kill.
 *
 * <p>Run on a host with kubectl access to the cluster:
 * <pre>{@code mvn -o exec:java -Dexec.mainClass=io.openkruise.agents.client.examples.SandboxTrafficJwtExample}</pre>
 */
public class SandboxTrafficJwtExample {

    private static final Charset UTF_8 = Charset.forName("UTF-8");
    private static final MediaType JSON_MEDIA_TYPE = MediaType.get("application/json; charset=utf-8");
    private static final DateTimeFormatter HMS = DateTimeFormatter.ofPattern("HH:mm:ss");

    private static String envOr(String key, String fallback) {
        String v = System.getenv(key);
        return (v == null || v.isEmpty()) ? fallback : v;
    }

    public static void main(String[] args) {
        String domain = System.getenv("E2B_DOMAIN");
        if (domain == null || domain.isEmpty()) {
            System.err.println("E2B_DOMAIN must be set");
            System.exit(1);
            return;
        }
        String apiKey = envOr("E2B_API_KEY", "");
        String protocol = envOr("E2B_PROTOCOL", "PRIVATE");
        String template = envOr("E2B_TEMPLATE", "code-interpreter");

        // https when SSL_CERT_FILE is set, matching the Python/Go demos.
        String certFile = System.getenv("SSL_CERT_FILE");
        boolean useHttps = certFile != null && !certFile.isEmpty();
        String scheme = envOr("E2B_SCHEME", useHttps ? "https" : "http");

        // The management URL the proxy forwards to. patch_e2b derives this as
        // {scheme}://{domain}/kruise/api (private path routing); E2B_API_URL is
        // an explicit override.
        String managerUrl = System.getenv("E2B_API_URL");
        if (managerUrl == null || managerUrl.isEmpty()) {
            managerUrl = scheme + "://" + domain + "/kruise/api";
        }

        String providerService = envOr("JWT_PROVIDER_SERVICE", "jwt-e2e-oidc-provider");
        String providerNamespace = envOr("JWT_PROVIDER_NAMESPACE", "sandbox-system");
        String forwardPort = envOr("JWT_PROVIDER_FORWARD_PORT", "18080");
        int validity = 65;
        String validityEnv = System.getenv("JWT_TOKEN_VALIDITY_SECONDS");
        if (validityEnv != null && !validityEnv.isEmpty()) {
            validity = Integer.parseInt(validityEnv);
            if (validity <= 0) {
                System.err.println("invalid JWT_TOKEN_VALIDITY_SECONDS " + validityEnv);
                System.exit(1);
                return;
            }
        }
        String providerBase = "http://127.0.0.1:" + forwardPort;
        String issueUrl = providerBase + "/issue";

        // One client trusts the CA bundle (https) and is reused for the proxy's
        // upstream forwarding and the provider /issue calls (plain http).
        OkHttpClient forwardClient;
        try {
            forwardClient = ("https".equals(scheme) && useHttps)
                ? trustingClient(certFile) : new OkHttpClient();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load SSL_CERT_FILE " + certFile, e);
        }

        System.out.println("========== Traffic JWT gateway demo (Java e2b SDK) ==========");
        System.out.printf("Manager: %s, domain: %s, scheme: %s, protocol: %s%n",
            managerUrl, domain, scheme, protocol);
        System.out.printf("Provider: %s/%s (kubectl port-forward %s), token validity: %ds%n",
            providerNamespace, providerService, forwardPort, validity);

        Process portForward = null;
        RefreshProxy proxy = null;
        SandboxApi api = null;
        String sandboxId = null;
        Sandbox sandbox = null;
        try {
            // [setup] port-forward the OIDC provider.
            System.out.println("\n[setup] port-forwarding the OIDC provider");
            portForward = startPortForward(providerService, providerNamespace, forwardPort);
            waitForProvider(providerBase + "/", forwardClient);

            // [setup] local refresh-translating proxy. The sandbox UID is looked
            // up with kubectl on first use and cached (it never changes).
            System.out.println("[setup] starting the refresh-translating proxy");
            proxy = new RefreshProxy(managerUrl, issueUrl, validity, forwardClient);
            proxy.start();
            String proxyUrl = proxy.baseUrl();
            System.out.printf("       proxy listening on %s (refresh -> %s)%n", proxyUrl, issueUrl);

            // Management + refresh route through the proxy; the data plane goes
            // straight to the gateway via domain/scheme/protocol.
            ConnectionConfig.Builder builder = new ConnectionConfig.Builder()
                .domain(domain)
                .scheme(scheme)
                .protocol(ConnectionConfig.Protocol.valueOf(protocol.toUpperCase()))
                .apiKey(apiKey)
                .apiURL(proxyUrl);
            if ("https".equals(scheme) && useHttps) {
                builder.httpClient(trustingClient(certFile));
            }
            ConnectionConfig config = builder.build();
            api = new SandboxApi(config);

            // [setup] create the sandbox with the JWT opt-in annotation. The
            // proxy swaps the OSS manager's opaque UUID for a real JWT on the
            // create response, so the SDK seeds its manager and every data-plane
            // call carries the traffic header.
            System.out.println("\n[setup] creating sandbox with the JWT opt-in annotation");
            NewSandbox body = new NewSandbox()
                .templateID(template)
                .timeout(600)
                .putMetadataItem(TrafficTokenManager.JWT_AUTH_METADATA_KEY, "true");
            sandbox = api.create(body);
            sandboxId = sandbox.getSandboxID();
            System.out.println("       sandbox created: " + sandboxId);

            // [1] data plane with the injected Traffic JWT.
            System.out.println("\n[1] data plane with an externally issued Traffic JWT");
            CommandResult cmd = sandbox.commands.run("echo 'hello with traffic jwt'");
            System.out.println("    command output: " + cmd.getStdout().trim());
            Execution exec = sandbox.codeInterpreter.runCode(
                "print('hello from jupyter with traffic jwt')");
            System.out.println("    jupyter output: " + String.join("", exec.getLogs().getStdout()).trim());

            // [2] the public traffic-token API.
            System.out.println("\n[2] traffic access token API");
            System.out.println("    cached token: " + describeToken(sandbox.getTrafficAccessToken()));
            String forced = sandbox.refreshTrafficAccessToken();
            System.out.println("    refreshTrafficAccessToken() -> " + describeToken(forced));

            // [3] pause and reconnect: the connect response is re-seeded by the
            // proxy, so the resumed sandbox carries a fresh JWT again.
            System.out.println("\n[3] pause and reconnect");
            api.pause(sandboxId);
            sandbox.close();
            sandbox = api.connect(sandboxId);
            System.out.println("    reconnected; token: " + describeToken(sandbox.getTrafficAccessToken()));
            CommandResult resumed = sandbox.commands.run("echo 'hello after reconnect'");
            System.out.println("    command output: " + resumed.getStdout().trim());

            // [4] watch the token rotate automatically while the data plane stays up.
            System.out.printf("%n[4] automatic refresh with %ds validity%n", validity);
            System.out.println("    (the OSS manager's refresh endpoint returns UUIDs, so the");
            System.out.println("     local proxy routes refreshes to the external issuer)");
            long deadlineMs = System.currentTimeMillis() + Math.max(90, validity * 2) * 1000L;
            String current = sandbox.getTrafficAccessToken();
            int refreshes = 0;
            while (System.currentTimeMillis() < deadlineMs) {
                CommandResult keepalive = sandbox.commands.run("echo keepalive");
                if (!"keepalive".equals(keepalive.getStdout().trim())) {
                    throw new IllegalStateException("data plane broke during rotation watch");
                }
                String token = sandbox.getTrafficAccessToken();
                if (!token.equals(current)) {
                    refreshes++;
                    System.out.println("    refreshed -> " + describeToken(token) + " (data plane still up)");
                    current = token;
                    if (refreshes >= 2) {
                        break;
                    }
                }
                Thread.sleep(2000);
            }
            System.out.printf("    observed %d automatic refresh(es); data plane stayed alive%n", refreshes);

            System.out.println("\n========== Demo completed successfully ==========");
        } catch (Exception e) {
            System.err.println("Operation error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        } finally {
            if (sandbox != null) {
                sandbox.close();
            }
            if (api != null && sandboxId != null) {
                System.out.println("\n[cleanup] killing sandbox");
                try {
                    api.kill(sandboxId);
                    System.out.println("    sandbox killed: " + sandboxId);
                } catch (Exception e) {
                    System.out.println("    kill failed (sandbox may have timed out already): " + e.getMessage());
                }
            }
            if (proxy != null) {
                proxy.close();
            }
            if (portForward != null) {
                stopPortForward(portForward);
            }
        }
    }

    // --- TLS ---

    /** Builds an OkHttpClient that trusts only the PEM CA bundle at the given
     *  path, replacing the platform default trust store (self-signed envs). */
    private static OkHttpClient trustingClient(String certFile) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);
        try (InputStream in = new FileInputStream(certFile)) {
            int i = 0;
            for (Certificate cert : cf.generateCertificates(in)) {
                keyStore.setCertificateEntry("ca-" + i++, cert);
            }
        }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(keyStore);
        X509TrustManager trustManager = (X509TrustManager) tmf.getTrustManagers()[0];
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, new TrustManager[]{trustManager}, null);
        return new OkHttpClient.Builder()
            .sslSocketFactory(sslContext.getSocketFactory(), trustManager)
            .build();
    }

    // --- kubectl / provider plumbing ---

    private static Process startPortForward(String service, String namespace, String port) throws IOException {
        Process process = new ProcessBuilder(
            "kubectl", "port-forward", "svc/" + service, port + ":8080", "-n", namespace).start();
        // JDK 8 has no Redirect.DISCARD; drain the streams on daemon threads so
        // the child never blocks on a full pipe.
        gobble(process.getInputStream());
        gobble(process.getErrorStream());
        return process;
    }

    private static void stopPortForward(Process process) {
        if (process != null) {
            process.destroy();
        }
    }

    private static void gobble(final InputStream in) {
        Thread t = new Thread(() -> {
            byte[] buf = new byte[1024];
            try {
                while (in.read(buf) != -1) {
                    // discard
                }
            } catch (IOException ignored) {
                // stream closed when the process is destroyed
            }
        });
        t.setDaemon(true);
        t.start();
    }

    private static void waitForProvider(String baseUrl, OkHttpClient client) throws IOException {
        for (int i = 0; i < 30; i++) {
            Request request = new Request.Builder().url(baseUrl).get().build();
            try (Response response = client.newCall(request).execute()) {
                if (response.body() != null) {
                    response.body().bytes();
                }
                return; // any answer means the forward is up
            } catch (IOException e) {
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    throw new IOException("interrupted while waiting for the provider", ie);
                }
            }
        }
        throw new IOException("port-forward did not become ready within 30s");
    }

    private static String kubectl(String... args) throws IOException, InterruptedException {
        List<String> cmd = new ArrayList<>();
        cmd.add("kubectl");
        cmd.addAll(Arrays.asList(args));
        Process process = new ProcessBuilder(cmd).start();
        String out = readStream(process.getInputStream());
        String err = readStream(process.getErrorStream());
        int code = process.waitFor();
        if (code != 0) {
            throw new IOException("kubectl " + String.join(" ", args) + ": " + err.trim());
        }
        return out.trim();
    }

    /** Looks up the Kubernetes UID of a sandbox. Sandbox IDs have the form
     *  {@code <namespace>--<name>}. */
    private static String sandboxUID(String sandboxId) throws IOException, InterruptedException {
        int idx = sandboxId.indexOf("--");
        if (idx < 0) {
            throw new IOException("sandbox ID \"" + sandboxId + "\" is not in <namespace>--<name> form");
        }
        String namespace = sandboxId.substring(0, idx);
        String name = sandboxId.substring(idx + 2);
        return kubectl("get", "sandbox", name, "-n", namespace, "-o", "jsonpath={.metadata.uid}");
    }

    /** Mints a Traffic JWT through the external provider's /issue endpoint. */
    private static IssuedToken issueTrafficToken(String sandboxId, String uid, int validity,
        String issueUrl, OkHttpClient client) throws IOException {
        JsonObject payload = new JsonObject();
        payload.addProperty("sandboxId", sandboxId);
        payload.addProperty("sandboxUid", uid);
        payload.addProperty("validitySeconds", validity);
        Request request = new Request.Builder()
            .url(issueUrl)
            .post(RequestBody.create(payload.toString(), JSON_MEDIA_TYPE))
            .build();
        try (Response response = client.newCall(request).execute()) {
            String body = response.body() != null ? response.body().string() : "";
            if (!response.isSuccessful()) {
                throw new IOException("issue returned status " + response.code());
            }
            JsonObject json = JsonParser.parseString(body).getAsJsonObject();
            return new IssuedToken(
                json.get("accessToken").getAsString(),
                json.get("accessTokenExpiration").getAsString());
        }
    }

    private static final class IssuedToken {
        final String token;
        final String expiration; // raw provider value, passed through to the SDK

        IssuedToken(String token, String expiration) {
            this.token = token;
            this.expiration = expiration;
        }
    }

    // --- JWT display helpers ---

    /** Renders a JWT tail plus its exp/iat claims for display. */
    private static String describeToken(String token) {
        if (token == null || token.isEmpty()) {
            return "<none>";
        }
        String tail = token.length() > 16 ? token.substring(token.length() - 16) : token;
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            return "..." + tail;
        }
        try {
            String payload = new String(Base64.getUrlDecoder().decode(padBase64(parts[1])), UTF_8);
            JsonObject claims = JsonParser.parseString(payload).getAsJsonObject();
            StringBuilder sb = new StringBuilder("...").append(tail).append(" (expires ");
            if (claims.has("exp")) {
                sb.append(formatHms(claims.get("exp").getAsDouble()));
            }
            if (claims.has("iat")) {
                sb.append(", issued ").append(formatHms(claims.get("iat").getAsDouble()));
            }
            return sb.append(")").toString();
        } catch (Exception e) {
            return "..." + tail;
        }
    }

    private static String formatHms(double epochSeconds) {
        return OffsetDateTime.ofInstant(Instant.ofEpochSecond(Math.round(epochSeconds)), ZoneOffset.UTC)
            .format(HMS);
    }

    private static String padBase64(String s) {
        int mod = s.length() % 4;
        if (mod == 0) {
            return s;
        }
        StringBuilder sb = new StringBuilder(s);
        for (int i = mod; i < 4; i++) {
            sb.append('=');
        }
        return sb.toString();
    }

    // --- misc helpers ---

    private static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        byte[] tmp = new byte[4096];
        int n;
        while ((n = in.read(tmp)) != -1) {
            buf.write(tmp, 0, n);
        }
        in.close();
        return buf.toByteArray();
    }

    private static String readStream(InputStream in) throws IOException {
        return new String(readAll(in), UTF_8);
    }

    private static String trimTrailingSlash(String s) {
        int end = s.length();
        while (end > 0 && s.charAt(end - 1) == '/') {
            end--;
        }
        return s.substring(0, end);
    }

    /** Extracts and percent-decodes the sandbox ID from a refresh path of the
     *  form {@code /sandboxes/{id}/traffic-access-token}. */
    private static String extractSandboxIdFromRefreshPath(String path) {
        String s = path;
        String suffix = "/traffic-access-token";
        if (s.endsWith(suffix)) {
            s = s.substring(0, s.length() - suffix.length());
        }
        int idx = s.indexOf("/sandboxes/");
        if (idx >= 0) {
            s = s.substring(idx + "/sandboxes/".length());
        }
        while (s.startsWith("/")) {
            s = s.substring(1);
        }
        while (s.endsWith("/")) {
            s = s.substring(0, s.length() - 1);
        }
        try {
            return URLDecoder.decode(s, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            return s;
        }
    }

    // --- the local refresh-translating proxy ---

    /**
     * A man-in-the-middle between the SDK and the real sandbox-manager. Refresh
     * requests are translated into provider {@code /issue} calls; create/connect
     * responses have their {@code trafficAccessToken} replaced with a freshly
     * issued JWT (the SDK's only seed entry point); everything else is
     * reverse-proxied to the real manager.
     */
    private static final class RefreshProxy implements AutoCloseable {
        private final HttpServer server;
        private final String managerUrl;
        private final String issueUrl;
        private final int validity;
        private final OkHttpClient client;
        private final Map<String, String> uidCache = new ConcurrentHashMap<>();

        RefreshProxy(String managerUrl, String issueUrl, int validity, OkHttpClient client) throws IOException {
            this.managerUrl = trimTrailingSlash(managerUrl);
            this.issueUrl = issueUrl;
            this.validity = validity;
            this.client = client;
            this.server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            this.server.createContext("/", this::handle);
            this.server.setExecutor(Executors.newCachedThreadPool());
        }

        void start() {
            server.start();
        }

        String baseUrl() {
            return "http://127.0.0.1:" + server.getAddress().getPort();
        }

        private void handle(HttpExchange exchange) throws IOException {
            try {
                String path = exchange.getRequestURI().getPath();
                String method = exchange.getRequestMethod();
                if ("POST".equals(method) && path.endsWith("/traffic-access-token")) {
                    translateRefresh(exchange, path);
                    return;
                }
                // Inject a JWT into the create/connect response so the SDK seeds
                // its manager (Java has no WithTrafficAccessToken-style option).
                boolean inject = "POST".equals(method)
                    && (path.endsWith("/connect") || path.equals("/sandboxes") || path.endsWith("/sandboxes"));
                forward(exchange, inject);
            } finally {
                exchange.close();
            }
        }

        private void translateRefresh(HttpExchange exchange, String path) throws IOException {
            readAll(exchange.getRequestBody()); // drain the (empty) SDK request body
            String sandboxId = extractSandboxIdFromRefreshPath(path);
            byte[] body;
            int status;
            try {
                String uid = uidFor(sandboxId);
                IssuedToken issued = issueTrafficToken(sandboxId, uid, validity, issueUrl, client);
                JsonObject out = new JsonObject();
                out.addProperty("trafficAccessToken", issued.token);
                out.addProperty("trafficAccessTokenExpiration", issued.expiration);
                body = out.toString().getBytes(UTF_8);
                status = 200;
                exchange.getResponseHeaders().set("Content-Type", "application/json");
            } catch (Exception e) {
                body = ("refresh translation failed: " + e.getMessage()).getBytes(UTF_8);
                status = 502;
                exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
            }
            exchange.sendResponseHeaders(status, body.length);
            OutputStream out = exchange.getResponseBody();
            out.write(body);
            out.close();
        }

        private void forward(HttpExchange exchange, boolean injectJwt) throws IOException {
            String method = exchange.getRequestMethod();
            String path = exchange.getRequestURI().getPath();
            String query = exchange.getRequestURI().getQuery();
            String target = managerUrl + path + (query != null && !query.isEmpty() ? "?" + query : "");
            byte[] reqBody = readAll(exchange.getRequestBody());
            String contentTypeStr = exchange.getRequestHeaders().getFirst("Content-Type");
            MediaType contentType = contentTypeStr != null ? MediaType.parse(contentTypeStr) : JSON_MEDIA_TYPE;

            Request.Builder rb = new Request.Builder().url(target);
            for (Map.Entry<String, List<String>> entry : exchange.getRequestHeaders().entrySet()) {
                String name = entry.getKey();
                // Let OkHttp re-derive hop-by-hop headers and its own
                // Accept-Encoding (copying gzip would defeat transparent
                // decompression and corrupt the injected response body).
                if (name == null || name.equalsIgnoreCase("Host") || name.equalsIgnoreCase("Content-Length")
                    || name.equalsIgnoreCase("Connection") || name.equalsIgnoreCase("Transfer-Encoding")
                    || name.equalsIgnoreCase("Accept-Encoding")) {
                    continue;
                }
                for (String value : entry.getValue()) {
                    rb.header(name, value);
                }
            }
            RequestBody body;
            if (reqBody.length > 0) {
                body = RequestBody.create(reqBody, contentType);
            } else if ("POST".equals(method) || "PUT".equals(method) || "PATCH".equals(method)) {
                body = RequestBody.create(new byte[0], contentType);
            } else {
                body = null;
            }
            rb.method(method, body);

            try (Response resp = client.newCall(rb.build()).execute()) {
                byte[] respBody = resp.body() != null ? resp.body().bytes() : new byte[0];
                int status = resp.code();
                if (injectJwt && status >= 200 && status < 300 && respBody.length > 0) {
                    respBody = injectTrafficToken(respBody);
                }
                for (String name : resp.headers().names()) {
                    if (name.equalsIgnoreCase("Content-Length") || name.equalsIgnoreCase("Transfer-Encoding")
                        || name.equalsIgnoreCase("Connection") || name.equalsIgnoreCase("Content-Encoding")) {
                        continue;
                    }
                    exchange.getResponseHeaders().set(name, resp.header(name));
                }
                if (respBody.length > 0) {
                    exchange.sendResponseHeaders(status, respBody.length);
                    OutputStream out = exchange.getResponseBody();
                    out.write(respBody);
                    out.close();
                } else {
                    exchange.sendResponseHeaders(status, -1);
                }
            }
        }

        private byte[] injectTrafficToken(byte[] respBody) {
            try {
                JsonObject json = JsonParser.parseString(new String(respBody, UTF_8)).getAsJsonObject();
                JsonElement idElement = json.get("sandboxID");
                if (idElement == null || !idElement.isJsonPrimitive()) {
                    return respBody; // cannot seed without a sandbox ID
                }
                String sandboxId = idElement.getAsString();
                String uid = uidFor(sandboxId);
                IssuedToken issued = issueTrafficToken(sandboxId, uid, validity, issueUrl, client);
                json.addProperty("trafficAccessToken", issued.token);
                return json.toString().getBytes(UTF_8);
            } catch (Exception e) {
                // Best effort: fall back to the manager's original (UUID) token,
                // which degrades the SDK to legacy behavior.
                System.err.println("[proxy] JWT injection failed: " + e.getMessage());
                return respBody;
            }
        }

        private String uidFor(String sandboxId) throws IOException, InterruptedException {
            String cached = uidCache.get(sandboxId);
            if (cached != null) {
                return cached;
            }
            String uid = sandboxUID(sandboxId);
            uidCache.put(sandboxId, uid);
            return uid;
        }

        @Override
        public void close() {
            server.stop(0);
        }
    }
}
