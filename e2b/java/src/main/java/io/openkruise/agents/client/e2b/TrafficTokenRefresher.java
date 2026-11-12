package io.openkruise.agents.client.e2b;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.time.OffsetDateTime;
import java.util.Map;

/**
 * Fetches a fresh traffic access token for a sandbox from the management API:
 *
 * <pre>POST {trafficAPIBase}/sandboxes/{sandboxID}/traffic-access-token</pre>
 *
 * <p>The upstream sandbox-manager registers this endpoint only under its
 * {@code /kruise/api} prefix (not on the native {@code https://api.<domain>}
 * path), so the base is resolved via {@link ConnectionConfig#getTrafficAPIBase()}
 * -- constant {@code {scheme}://{domain}/kruise/api} across routing protocols,
 * mirroring the Python patch -- instead of the protocol-dependent
 * {@link ConnectionConfig#getAPIURL()}. An explicit {@code apiURL} override
 * still wins.
 *
 * <p>This endpoint is hand-written against the shared {@code ApiClient} (the
 * OpenAPI generator does not emit it), so it reuses the same HTTP client and
 * X-API-Key authentication as every other management call. On failure the
 * response body is not surfaced (to avoid leaking server error details into
 * client logs); the status code and Retry-After delay are preserved in a
 * {@link TrafficAccessTokenRefreshException} instead.
 *
 * <p>The Java counterpart of the Go SDK's
 * {@code SandboxApi.RefreshTrafficAccessToken} and the Python patch's
 * {@code _sync_refresh}.
 */
public final class TrafficTokenRefresher {

    private static final MediaType JSON_MEDIA_TYPE = MediaType.get("application/json; charset=utf-8");
    private static final String TOKEN_FIELD = "trafficAccessToken";
    private static final String EXPIRATION_FIELD = "trafficAccessTokenExpiration";

    private TrafficTokenRefresher() {
    }

    /**
     * Requests a fresh traffic access token for {@code sandboxID}.
     *
     * @throws TrafficAccessTokenRefreshException on transport failure or a non-2xx status
     * @throws TrafficAccessTokenException        on a malformed/empty response or bad expiration
     */
    public static TrafficAccessToken refresh(ConnectionConfig config, String sandboxID)
        throws TrafficAccessTokenException {
        String refreshUrl = String.format("%s/sandboxes/%s/traffic-access-token",
            config.getTrafficAPIBase(), encodePathSegment(sandboxID));

        OkHttpClient client = config.getOrCreateApiClient().getHttpClient();

        Request.Builder requestBuilder = new Request.Builder()
            .url(refreshUrl)
            .post(RequestBody.create("", JSON_MEDIA_TYPE));
        // Custom connection headers ride along, mirroring _refresh_headers in
        // the Python kruise_agents patch; X-API-Key is applied last so it wins
        // on a collision.
        Map<String, String> headers = config.getHeaders();
        if (headers != null) {
            for (Map.Entry<String, String> entry : headers.entrySet()) {
                requestBuilder.header(entry.getKey(), entry.getValue());
            }
        }
        String apiKey = config.getApiKey();
        if (apiKey != null && !apiKey.isEmpty()) {
            requestBuilder.header("X-API-Key", apiKey);
        }

        try (Response response = client.newCall(requestBuilder.build()).execute()) {
            int status = response.code();
            if (status < 200 || status >= 300) {
                double retryAfter = TrafficTokenManager.parseRetryAfter(response.header("Retry-After"));
                throw new TrafficAccessTokenRefreshException(
                    "traffic access token refresh failed with status " + status, status, retryAfter);
            }
            return parseRefreshResponse(response);
        } catch (TrafficAccessTokenException e) {
            // Domain failures (bad status, malformed response) propagate as-is.
            throw e;
        } catch (IOException e) {
            // Transport-level failure building/sending the request or reading the body.
            throw new TrafficAccessTokenRefreshException(
                "traffic access token refresh request failed", 0, 0, e);
        }
    }

    private static TrafficAccessToken parseRefreshResponse(Response response) throws IOException {
        ResponseBody body = response.body();
        String bodyString = (body != null) ? body.string() : "";

        JsonObject payload;
        try {
            JsonElement element = JsonParser.parseString(bodyString);
            if (!element.isJsonObject()) {
                throw new TrafficAccessTokenException(
                    "traffic access token refresh returned a malformed response");
            }
            payload = element.getAsJsonObject();
        } catch (JsonSyntaxException e) {
            throw new TrafficAccessTokenException(
                "traffic access token refresh returned a malformed response", e);
        }

        String token = stringField(payload, TOKEN_FIELD);
        if (token == null || token.isEmpty()) {
            throw new TrafficAccessTokenException("traffic access token refresh returned an empty token");
        }
        OffsetDateTime expiresAt = TrafficTokenManager.parseTrafficTokenExpiration(
            stringField(payload, EXPIRATION_FIELD));
        double expiresAtSeconds = expiresAt.toEpochSecond() + expiresAt.getNano() / 1_000_000_000.0;
        return new TrafficAccessToken(token, expiresAtSeconds);
    }

    private static String stringField(JsonObject object, String name) {
        JsonElement element = object.get(name);
        if (element == null || element.isJsonNull() || !element.isJsonPrimitive()) {
            return null;
        }
        return element.getAsString();
    }

    /**
     * Percent-encodes a sandbox ID for use as a single URL path segment, the
     * counterpart of Go's {@code url.PathEscape}. Real sandbox IDs are
     * alphanumeric, so this matches Go byte-for-byte in practice.
     */
    private static String encodePathSegment(String value) {
        try {
            // URLEncoder targets form encoding (space -> '+'); a path segment
            // needs '%20' instead.
            return URLEncoder.encode(value, "UTF-8").replace("+", "%20");
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("UTF-8 not available", e);
        }
    }
}
