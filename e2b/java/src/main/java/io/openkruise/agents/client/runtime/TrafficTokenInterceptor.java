package io.openkruise.agents.client.runtime;

import okhttp3.Interceptor;
import okhttp3.Request;
import okhttp3.Response;

import java.io.IOException;

/**
 * OkHttp application interceptor that attaches the sandbox traffic access
 * token to every data-plane request. It obtains the token from a
 * {@link TrafficTokenProvider} immediately before the request is sent, so a
 * short-lived Traffic JWT is refreshed transparently.
 *
 * <p>When the provider returns an empty (or {@code null}) token the request
 * proceeds unchanged (no {@code e2b-traffic-access-token} header), preserving
 * the legacy behavior of sandboxes that are not JWT-protected. When the
 * provider throws, the exception propagates and the request is never sent
 * (fail-closed).
 *
 * <p>Every data-plane client (Commands, Filesystem, CodeInterpreter) shares
 * the OkHttp clients built by {@link RuntimeConfig}, so installing this
 * interceptor on those clients covers all data-plane traffic. It is the Java
 * counterpart of the Go SDK's {@code trafficTokenTransport} RoundTripper
 * wrapper and the Python patch's request hooks / gRPC interceptors.
 */
public final class TrafficTokenInterceptor implements Interceptor {

    /** Header carrying the sandbox traffic access token on data-plane requests. */
    public static final String TRAFFIC_TOKEN_HEADER = "e2b-traffic-access-token";

    private final TrafficTokenProvider provider;

    public TrafficTokenInterceptor(TrafficTokenProvider provider) {
        if (provider == null) {
            throw new IllegalArgumentException("provider cannot be null");
        }
        this.provider = provider;
    }

    @Override
    public Response intercept(Chain chain) throws IOException {
        Request original = chain.request();
        String token = provider.get();
        if (token == null || token.isEmpty()) {
            return chain.proceed(original);
        }
        Request withToken = original.newBuilder()
            .header(TRAFFIC_TOKEN_HEADER, token)
            .build();
        return chain.proceed(withToken);
    }
}
