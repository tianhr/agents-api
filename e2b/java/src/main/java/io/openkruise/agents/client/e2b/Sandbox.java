package io.openkruise.agents.client.e2b;

import io.openkruise.agents.client.runtime.codeinterpreter.CodeInterpreter;
import io.openkruise.agents.client.runtime.RuntimeClient;
import io.openkruise.agents.client.runtime.RuntimeConfig;
import io.openkruise.agents.client.runtime.commands.Commands;
import io.openkruise.agents.client.runtime.filesystem.Filesystem;

import java.util.concurrent.atomic.AtomicReference;

/**
 * Represents a created/connected E2B sandbox instance (data plane).
 * Supports try-with-resources for automatic resource cleanup (HTTP connection + thread pools).
 * Does NOT terminate the sandbox on close — use {@code sandboxApi.kill(sandboxID)} to terminate.
 */
public class Sandbox implements AutoCloseable {

    /** Command execution within the sandbox */
    public final Commands commands;
    /** File operations within the sandbox */
    public final Filesystem files;
    /** Code interpreter for executing code in the sandbox */
    public final CodeInterpreter codeInterpreter;

    private final String sandboxID;
    private final ConnectionConfig config;
    private final RuntimeClient runtimeClient;

    // Holds the traffic token manager once installed; null until the sandbox is
    // known to be JWT-protected (token returned by the management API or
    // enable-jwt-auth metadata). Read atomically since the data-plane
    // interceptor reads it on every request.
    private final AtomicReference<TrafficTokenManager> trafficToken = new AtomicReference<>();

    Sandbox(String sandboxID, String envdAccessToken, ConnectionConfig config) {
        this.sandboxID = sandboxID;
        this.config = config;

        // The traffic token provider is installed up front even though the
        // manager may only be attached later (by SandboxApi.create/connect): it
        // reads the AtomicReference on every data-plane request and returns ""
        // (no header) while no manager exists, preserving legacy behavior.
        RuntimeConfig runtimeConfig = ConnectionConfig.toRuntimeConfig(
            config, envdAccessToken, this::trafficTokenProvider);
        this.runtimeClient = RuntimeClient.create(sandboxID, runtimeConfig);
        this.commands = runtimeClient.commands;
        this.files = runtimeClient.files;
        this.codeInterpreter = runtimeClient.codeInterpreter;
    }

    /**
     * Attaches a traffic token manager seeded with {@code token} ("" to
     * bootstrap via the first refresh). Non-JWT tokens (legacy opaque UUIDs) and
     * debug mode keep the legacy behavior: no traffic header, no refresh.
     * Installing twice is a no-op, mirroring the Python patch's lazy-install
     * guard and the Go SDK's {@code installTrafficTokenManager}.
     */
    void installTrafficTokenManager(String token) {
        if (config.isDebug() || trafficToken.get() != null) {
            return;
        }
        TrafficTokenManager manager;
        try {
            manager = new TrafficTokenManager(token, this::refreshTrafficToken);
        } catch (TrafficAccessTokenException e) {
            // Seed token is not a JWT: legacy deployment, no automatic refresh.
            return;
        }
        trafficToken.set(manager);
    }

    /**
     * Adapts the sandbox's traffic token manager to the runtime
     * {@code TrafficTokenProvider}: every data-plane request obtains a valid
     * token (refreshing when needed) right before it is sent. Without a manager
     * it returns an empty token, which the interceptor skips (legacy sandboxes
     * send no traffic header).
     */
    private String trafficTokenProvider() throws TrafficAccessTokenException {
        TrafficTokenManager manager = trafficToken.get();
        if (manager != null) {
            return manager.ensureValidToken(false);
        }
        return "";
    }

    /** Fetches a fresh traffic access token for this sandbox from the management API. */
    private TrafficAccessToken refreshTrafficToken() throws TrafficAccessTokenException {
        return TrafficTokenRefresher.refresh(config, sandboxID);
    }

    /**
     * Returns the currently cached traffic access token without triggering a
     * refresh, or "" when the sandbox is not JWT-protected.
     */
    public String getTrafficAccessToken() {
        TrafficTokenManager manager = trafficToken.get();
        return (manager != null) ? manager.currentToken() : "";
    }

    /**
     * Forces a refresh of the traffic access token and returns the fresh token.
     * Concurrent forced refreshes coalesce into a single refresh; a failed
     * refresh still returns the current token when it has not expired (and
     * throws otherwise).
     *
     * @throws TrafficAccessTokenException if the sandbox is not JWT-protected, or
     *         the token expired before it could be refreshed
     */
    public String refreshTrafficAccessToken() throws TrafficAccessTokenException {
        TrafficTokenManager manager = trafficToken.get();
        if (manager == null) {
            throw new TrafficAccessTokenException("sandbox " + sandboxID + " has no traffic access token");
        }
        return manager.ensureValidToken(true);
    }

    public String getSandboxID() {
        return sandboxID;
    }

    public ConnectionConfig getConfig() {
        return config;
    }

    public String getSandboxURL() {
        return config.getSandboxURL(sandboxID);
    }

    public RuntimeClient getRuntimeClient() {
        return runtimeClient;
    }

    /** Closes the HTTP connection and releases thread pools. Does NOT terminate the sandbox. */
    @Override
    public void close() {
        if (runtimeClient != null) {
            runtimeClient.close();
        }
    }

    @Override
    public String toString() {
        return "Sandbox{sandboxID='" + sandboxID + "'}";
    }
}
