# VNC Library for Go

go-vnc is a VNC client library for Go.

It implements [RFC 6143][RFC6143] (The Remote Framebuffer Protocol) and the
[VeNCrypt](docs/vencrypt.md) security type (TLS/X.509 wrapping of None or VNC
authentication).

## Setup

The module path is `github.com/alexsnet/go-vnc`. With Go modules (Go 1.20+):

```
go get github.com/alexsnet/go-vnc
```

Run the tests with:

```
go test ./...
```

## Usage

Sample usage is in the package documentation (`doc.go`) and on
[pkg.go.dev][GoDoc].

A typical client:

1. Dials the VNC server with `net.Dial`.
2. Builds a `ClientConfig` with `NewClientConfig(password)`.
3. Sets `ServerMessageCh` if it wants to receive parsed server messages.
4. Calls `Connect`, then `ListenAndHandle` and `FramebufferUpdateRequest`.

```go
vcc := vnc.NewClientConfig("some_password")
vcc.ServerMessageCh = make(chan vnc.ServerMessage, 16)
vc, err := vnc.Connect(ctx, nc, vcc)
```

`NewClientConfig` enables security types None, VNC authentication, and VeNCrypt.
VeNCrypt prefers X509Vnc, then TLSVnc, then the None variants. TLS certificate
verification is currently skipped (`InsecureSkipVerify`); treat the transport as
authenticated only as far as the inner VNC password.

## Source layout

Files follow RFC 6143 section numbers:

- [7.1] handshake.go — ProtocolVersion, Security, SecurityResult
- [7.2] security.go — None and VNC authentication
- [7.3] initialization.go — ClientInit / ServerInit
- [7.4] pixel_format.go
- [7.5] client.go — client-to-server messages
- [7.6] server.go — server-to-client messages
- [7.7] encodings.go

Additional files:

- vncclient.go — `Connect`, `ClientConn`, I/O helpers
- vencrypt.go — VeNCrypt (security type 19)
- common.go — errors, buffers, UI settle delay
- docs/vencrypt.md — VeNCrypt wire format

<!--- Links -->
[RFC6143]: https://tools.ietf.org/html/rfc6143
[GoDoc]: https://pkg.go.dev/github.com/alexsnet/go-vnc
