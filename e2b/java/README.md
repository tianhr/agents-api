# E2B Java Client

Java client library for E2B Sandbox management, providing both control plane (sandbox lifecycle) and data plane (runtime
operations) APIs.

## Installation

```xml

<dependency>
    <groupId>io.openkruise</groupId>
    <artifactId>agents-client-e2b</artifactId>
    <version>0.6.0</version>
</dependency>
```

## Overview

| Class              | Description                                                                                        |
|--------------------|----------------------------------------------------------------------------------------------------|
| `ConnectionConfig` | Connection configuration with Builder pattern, supports environment variables, custom OkHttpClient |
| `SandboxApi`       | Control plane: create, connect, list, kill, pause, setTimeout                                      |
| `Sandbox`          | Data plane entry: commands, files, codeInterpreter                                                 |
| `SandboxInfo`      | Immutable sandbox information returned by list/getInfo                                             |

## Quick Start

```java
import io.openkruise.agents.client.e2b.*;

// Reads E2B_API_KEY and E2B_DOMAIN from environment variables
ConnectionConfig config = new ConnectionConfig.Builder().build();
SandboxApi api = new SandboxApi(config);

// Create → Use → Close connection + Explicitly kill sandbox
Sandbox sandbox = api.create("code-interpreter");
try (sandbox) {
    sandbox.commands.run("echo hello");
    sandbox.files.writeText("/tmp/demo.txt", "Hello!");
} finally {
    api.kill(sandbox.getSandboxID());
}
```

## Documentation

- [English Documentation](src/main/java/io/openkruise/agents/client/e2b/README.md) — Full API reference with examples
- [中文文档](src/main/java/io/openkruise/agents/client/e2b/README_zh-CH.md) — 完整 API 参考及示例

## Examples

- [Lifecycle Management](src/main/java/io/openkruise/agents/client/examples/SandboxApiManagerExample.java)
- [Commands](src/main/java/io/openkruise/agents/client/examples/SandboxCommandsExample.java)
- [Run as User](src/main/java/io/openkruise/agents/client/examples/SandboxRunAsUserExample.java)
- [Files](src/main/java/io/openkruise/agents/client/examples/SandboxFilesExample.java)
- [Code Interpreter](src/main/java/io/openkruise/agents/client/examples/SandboxCodeInterpreterExample.java)
- [Traffic JWT](src/main/java/io/openkruise/agents/client/examples/SandboxTrafficJwtExample.java)

## Environment Variables

| Variable      | Description                                 |
|---------------|---------------------------------------------|
| `E2B_API_KEY` | API key for authentication                  |
| `E2B_DOMAIN`  | E2B API domain (default: `your.domain.com`) |

## Traffic JWT Refresh

Sandboxes created with metadata `security.agents.kruise.io/enable-jwt-auth=true` are protected by a short-lived
**Traffic JWT**. The SDK attaches and refreshes it automatically on every data-plane request (Commands / Filesystem /
CodeInterpreter) — no caller code change is required:

```java
NewSandbox body = new NewSandbox()
    .templateID("code-interpreter")
    .putMetadataItem("security.agents.kruise.io/enable-jwt-auth", "true");
Sandbox sandbox = api.create(body);
sandbox.commands.run("echo hi");                 // carries + refreshes the token automatically

String token = sandbox.getTrafficAccessToken();  // cached token ("" when not JWT-protected)
token = sandbox.refreshTrafficAccessToken();     // force a refresh
```

Non-JWT sandboxes and `debug` mode keep the legacy behavior (no `e2b-traffic-access-token` header, no refresh). See
the [full docs](src/main/java/io/openkruise/agents/client/e2b/README.md#8-traffic-jwt-refresh) and
[`SandboxTrafficJwtExample`](src/main/java/io/openkruise/agents/client/examples/SandboxTrafficJwtExample.java) for the
mechanism, refresh-URL routing, rollout, and an end-to-end gateway demo.
