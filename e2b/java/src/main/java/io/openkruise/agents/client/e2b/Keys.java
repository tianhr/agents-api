package io.openkruise.agents.client.e2b;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * E2B SDK key-compat encoding.
 *
 * <p>Mirrors the Python {@code kruise_agents} keys module, the Go SDK's
 * {@code e2b/keys.go} and the upstream sandbox-manager's
 * {@code pkg/servers/e2b/keys/compat.go}; the golden values are byte-for-byte
 * identical across all of them, locking wire-format parity across the SDKs.
 */
public final class Keys {

    // E2B SDK key-compat encoding constants. These must stay in sync with the
    // Python kruise_agents keys module and the upstream sandbox-manager's
    // pkg/servers/e2b/keys/compat.go.
    static final String E2B_SDK_COMPAT_PREFIX = "e2b_";
    // E2B_SDK_COMPAT_MAGIC hex-encodes the ASCII bytes "okag" ("ok" + "ag[ents]").
    static final String E2B_SDK_COMPAT_MAGIC = "6f6b6167";
    // E2B_SDK_COMPAT_VERSION is the single released format version.
    static final String E2B_SDK_COMPAT_VERSION = "01";
    // E2B_SDK_COMPAT_CHECKSUM_SALT namespaces the checksum so encoded keys from
    // unrelated schemes cannot collide.
    static final String E2B_SDK_COMPAT_CHECKSUM_SALT = "openkruise-agents/e2b-key-compat/v1";

    private Keys() {
    }

    /**
     * Wraps a raw OpenKruise Agents API key (UUID or admin key) in an E2B
     * SDK-compatible form. Use it when feeding a raw key to a client that
     * enforces the official E2B key format; this SDK sends raw keys as-is and
     * never needs the wrapper itself.
     *
     * <p>Inputs larger than 4 GB would overflow the 8-hex-character length
     * field; real keys are far below that and the overflow is part of the wire
     * format definition (no runtime guard, matching the reference
     * implementations).
     *
     * @param raw the raw API key
     * @return the E2B SDK-compatible encoded key
     */
    public static String encodeForE2BSDK(String raw) {
        byte[] rawBytes = raw.getBytes(StandardCharsets.UTF_8);

        byte[] saltBytes = E2B_SDK_COMPAT_CHECKSUM_SALT.getBytes(StandardCharsets.UTF_8);
        byte[] checksumPayload = new byte[saltBytes.length + rawBytes.length];
        System.arraycopy(saltBytes, 0, checksumPayload, 0, saltBytes.length);
        System.arraycopy(rawBytes, 0, checksumPayload, saltBytes.length, rawBytes.length);
        byte[] digest = sha256(checksumPayload);

        // Length is rendered as 8 lowercase hex digits; lowercase is stable for
        // every value because %08x never emits uppercase letters.
        String body = toHex(rawBytes);
        // The checksum is always the first 8 bytes of the digest (16 hex chars).
        String checksum = toHex(Arrays.copyOf(digest, 8));
        return String.format("%s%s%s%08x%s%s",
            E2B_SDK_COMPAT_PREFIX,
            E2B_SDK_COMPAT_MAGIC,
            E2B_SDK_COMPAT_VERSION,
            rawBytes.length,
            body,
            checksum);
    }

    private static byte[] sha256(byte[] payload) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(payload);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is mandated by the JCA specification; never absent.
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }
}
