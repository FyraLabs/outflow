# Outflow

Outflow is a Windows-to-Unix socket shim that allows applications running under Wine to communicate with Unix domain sockets or UDP endpoints. It supports both client and server modes, enabling bidirectional communication.

This tool takes advantage of Wine 10's new `AF_UNIX` socket support, allowing named pipes to be exposed outside the Wineprefix
as Unix domain sockets. It also supports sending data to/from UDP endpoints for piping over the network.

Outflow is meant to be run inside the Wine environment, forwarding data to Linux.

## Key Features

- **Truly non-blocking forwarding**: Uses `PeekNamedPipe` for named pipe checking and non-blocking sockets with proper error handling
- **Multiple output modes**: Supports both Unix domain sockets and UDP output
- **Bidirectional communication**: Optional full-duplex proxying between named pipe and socket/UDP
- **Named pipe server mode**: Can create named pipe servers that accept multiple client connections
- **Configurable poll interval**: Adjust polling frequency in microseconds for optimal latency vs CPU usage balance
- **Partial send handling**: Properly handles cases where socket sends might be partial in non-blocking mode
- **Adaptive client/server mode**: For Unix sockets, automatically detects existing sockets and runs as client, creates server if none exists
- **Configurable parameters**: Buffer size, retry intervals, poll intervals, and log levels via CLI or environment variables
- **Persistent server**: Unix socket mode continues

## Running

You must execute Outflow inside a Wine environment. For example:

```bash
wine outflow.exe --pipe "\\.\pipe\my_app" --socket "/tmp/my_app.sock"
```

This will expose the named pipe to the Unix domain socket specified outside the Wineprefix.
It will also create the socket if it does not already exist, or connect to it if it does.

> [!NOTE]
> Wine currently does not have the ability to detect and unlink existing Unix domain sockets, so you must ensure the socket does not already exist before running Outflow.
> If you run Outflow and a stale socket file exists from a previous run, it will fail to start with a `WSAEADDRINUSE` error.
> You may work around this by creating a socket listener on the Linux side (using `socat` or similar), since Outflow will automatically detect if the socket is already in use and run in client mode instead.
>
> ```bash
> rm -f /tmp/my_app.sock
> wine outflow.exe --pipe "\\.\pipe\my_app" --socket "/tmp/my_app.sock"
> ```
>
> Or, using `socat` to create a listener to forward to somewhere else:
>
> ```bash
> socat UNIX-LISTEN:/tmp/my_app.sock,fork,reuseaddr EXEC:"cat"
> wine outflow.exe --pipe "\\.\pipe\my_app" --socket "/tmp/my_app.sock"
> ```

## Output Modes

### Unix Domain Socket Mode (Default)

Forwards data to Unix domain sockets with client/server detection.

### UDP Mode

Forwards data directly to a UDP endpoint - simpler setup, no client/server coordination needed.

## Command Line Arguments

### Basic usage with custom pipe and socket

```bash
outflow --pipe "\\.\pipe\my_app" --socket "/tmp/my_app.sock"
```

### With custom buffer size and retry interval

```bash
outflow --pipe "\\.\pipe\chuni_led" --socket "/tmp/chuni.sock" --buffer-size 1024 --retry-interval 500
```

### Set log level to info for less verbose output

```bash
outflow --log-level info
```

### UDP mode usage

```bash
outflow --pipe "\\.\pipe\my_app" --udp --udp-ip "192.168.1.100" --udp-port 8080
```

### UDP mode with default localhost

```bash
outflow --pipe "\\.\pipe\my_app" --udp --udp-port 12345
```

### Create named pipe if missing

```bash
outflow --pipe "\\.\pipe\my_app" --socket "/tmp/my_app.sock" --create-pipe
```

### Bidirectional communication mode

```bash
outflow --pipe "\\.\pipe\my_app" --socket "/tmp/my_app.sock" --bidirectional
```

### Bidirectional UDP mode

```bash
outflow --pipe "\\.\pipe\my_app" --udp --udp-port 12345 --bidirectional
```

## Named Pipe Creation

By default, Outflow expects the named pipe to already exist (created by the Wine application). However, you can use the `--create-pipe` flag to have Outflow create a named pipe server and listen for client connections.

When using `--create-pipe`, Outflow:

1. Creates a named pipe server on Windows
2. Waits for Wine applications to connect to that pipe as clients  
3. Forwards any data written to the pipe by clients to the Unix socket or UDP endpoint
4. Supports multiple client connections (each gets its own pipe instance)
5. Continues running and accepting new connections when clients disconnect

This is useful when:

- You want the Wine application to write to a pipe that gets forwarded to Unix/UDP
- Multiple Wine applications need to send data to the same Unix endpoint
- You want to set up the pipe infrastructure before applications start
- You're building a service that aggregates data from multiple Wine processes

```bash
# Create pipe server that forwards to Unix socket
outflow --pipe "\\.\pipe\my_app" --socket "/tmp/my_app.sock" --create-pipe

# Create pipe server that forwards to UDP
outflow --pipe "\\.\pipe\my_app" --udp --udp-port 12345 --create-pipe
```

**Note**: When using `--create-pipe`, Outflow becomes the named pipe server, and Wine applications should connect as clients to that pipe. For the Unix socket side, you'll need an existing socket listener (Outflow connects as a client to the Unix socket).

## Environment Variables

### Set all configuration via environment variables

```bash
export WINE_PROXY_PIPE="\\.\pipe\chuni_led"
export WINE_PROXY_SOCKET="/tmp/chuni.sock"
export WINE_PROXY_BUFFER_SIZE=1024
export WINE_PROXY_RETRY_INTERVAL=500
export WINE_PROXY_LOG_LEVEL=info

outflow
```

### Mixed usage (environment + CLI override)

```bash
export WINE_PROXY_PIPE="\\.\pipe\default_pipe"
export WINE_PROXY_SOCKET="/tmp/default.sock"

# Override just the pipe name via CLI
outflow --pipe "\\.\pipe\special_pipe"
```

### UDP mode via environment variables

```bash
export WINE_PROXY_PIPE="\\.\pipe\chuni_led"
export WINE_PROXY_UDP=true
export WINE_PROXY_UDP_IP="192.168.1.50"
export WINE_PROXY_UDP_PORT=9999

outflow
```

## Use Cases

Outflow can be used to forward data from Windows named pipes to Unix domain sockets or UDP endpoints, enabling various use cases such as:

### Discord RPC integration

Forward presence data from a Wine application to Discord using a named pipe and Unix socket.
  
```bash
wine outflow.exe --create-pipe --pipe "\\.\pipe\discord-rpc-0" --socket "/run/user/1000/discord-rpc-0" # Assuming your UID is 1000
```

## Bidirectional Communication

When `--bidirectional` is enabled, the proxy forwards data in both directions:

- **Pipe → Socket/UDP**: Normal forwarding (same as unidirectional)
- **Socket/UDP → Pipe**: Receives data from the socket/UDP and writes it back to the named pipe

This enables full-duplex communication between the Wine application and the host system.

**Requirements for bidirectional mode:**

- The named pipe must support both read and write operations
- The Wine application must be able to handle data being written to the pipe
- For UDP mode, the proxy will listen for incoming UDP packets on the same socket

## Client-Server Behavior

The proxy automatically detects if a Unix socket already exists:

- **Server Mode**: Creates the socket and listens for connections
- **Client Mode**: Connects to existing socket and forwards data

This allows multiple Wine processes to forward data to the same socket for aggregation.

## Building

To build Outflow, you need a Rust toolchain installed.

You will also need either:

- `x86_64-w64-mingw32-gcc` for 64-bit Windows builds on Linux
- Visual Studio for native Windows builds

Run the following command to build:

```bash
cargo build --release
```

Or to specify a target for cross-compilation:

```bash
cargo build --release --target x86_64-pc-windows-gnu
```

The resulting binary will be located in `target/release/outflow.exe` or `target/x86_64-pc-windows-gnu/release/outflow.exe`.
