// VNC client implementation.

package vnc

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"reflect"

	"context"

	"github.com/alexsnet/go-vnc/go/metrics"
	"github.com/alexsnet/go-vnc/messages"
)

// bufConn reads leftover bytes from a bufio.Reader, then from the
// underlying connection. Writes go directly to the connection.
type bufConn struct {
	net.Conn
	r io.Reader
}

func (c *bufConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

// Connect negotiates a connection to a VNC server.
func Connect(ctx context.Context, c net.Conn, cfg *ClientConfig) (*ClientConn, error) {
	conn := NewClientConn(c, cfg)

	if err := conn.processContext(ctx); err != nil {
		conn.Close()
		return nil, err
	}

	if err := conn.protocolVersionHandshake(ctx); err != nil {
		conn.Close()
		return nil, err
	}
	if err := conn.securityHandshake(); err != nil {
		conn.Close()
		return nil, err
	}
	if err := conn.securityResultHandshake(); err != nil {
		conn.Close()
		return nil, err
	}
	if err := conn.clientInit(); err != nil {
		conn.Close()
		return nil, err
	}
	if err := conn.serverInit(); err != nil {
		conn.Close()
		return nil, err
	}

	// Send client-to-server messages.
	encs := conn.encodings
	if err := conn.SetEncodings(encs); err != nil {
		conn.Close()
		return nil, Errorf("failure calling SetEncodings; %s", err)
	}

	pf := conn.pixelFormat
	if err := conn.SetPixelFormat(pf); err != nil {
		conn.Close()
		return nil, Errorf("failure calling SetPixelFormat; %s", err)
	}

	return conn, nil
}

// A ClientConfig structure is used to configure a ClientConn. After
// one has been passed to initialize a connection, it must not be modified.
type ClientConfig struct {
	secType uint8 // The negotiated security type.

	// A slice of ClientAuth methods. Only the first instance that is
	// suitable by the server will be used to authenticate.
	Auth []ClientAuth

	// Password for servers that require authentication.
	Password string

	// Logger
	Logger *log.Logger

	// Exclusive determines whether the connection is shared with other
	// clients. If true, then all other clients connected will be
	// disconnected when a connection is established to the VNC server.
	Exclusive bool

	// The channel that all messages received from the server will be
	// sent on. If the channel blocks, then the goroutine reading data
	// from the VNC server may block indefinitely. It is up to the user
	// of the library to ensure that this channel is properly read.
	// If this is not set, then all messages will be discarded.
	ServerMessageCh chan ServerMessage

	// A slice of supported messages that can be read from the server.
	// This only needs to contain NEW server messages, and doesn't
	// need to explicitly contain the RFC-required messages.
	ServerMessages []ServerMessage
}

// NewClientConfig returns a populated ClientConfig.
func NewClientConfig(p string) *ClientConfig {
	return &ClientConfig{
		Auth: []ClientAuth{
			&ClientAuthNone{},
			&ClientAuthVNC{p},
			&ClientAuthVeNCryptAuth{},
		},
		Password: p,
		ServerMessages: []ServerMessage{
			&FramebufferUpdate{},
			&SetColorMapEntries{},
			&Bell{},
			&ServerCutText{},
		},
	}
}

// The ClientConn type holds client connection information.
type ClientConn struct {
	Conn            net.Conn
	bufr            *bufio.Reader
	config          *ClientConfig
	protocolVersion string

	connTerminated bool

	log *log.Logger

	// If the pixel format uses a color map, then this is the color
	// map that is used. This should not be modified directly, since
	// the data comes from the server.
	// Definition in §5 - Representation of Pixel Data.
	colorMap ColorMap

	// Name associated with the desktop, sent from the server.
	desktopName string

	// Encodings supported by the client. This should not be modified
	// directly. Instead, SetEncodings() should be used.
	encodings Encodings

	// Height of the frame buffer in pixels, sent from the server.
	fbHeight uint16

	// Width of the frame buffer in pixels, sent from the server.
	fbWidth uint16

	// The pixel format associated with the connection. This shouldn't
	// be modified. If you wish to set a new pixel format, use the
	// SetPixelFormat method.
	pixelFormat PixelFormat

	// Security types, supported by the server
	securityTypes []uint8

	// Track metrics on system performance.
	metrics map[string]metrics.Metric
}

func NewClientConn(c net.Conn, cfg *ClientConfig) *ClientConn {
	conn := &ClientConn{
		connTerminated: false,
		config:         cfg,
		log:            cfg.Logger,
		encodings:      Encodings{&RawEncoding{}},
		pixelFormat:    PixelFormat32bit,
		metrics: map[string]metrics.Metric{
			"bytes-received": &metrics.Gauge{},
			"bytes-sent":     &metrics.Gauge{},
		},
	}
	conn.setConn(c)
	return conn
}

// setConn updates the underlying connection and rebuilds the buffered reader.
func (c *ClientConn) setConn(conn net.Conn) {
	c.Conn = conn
	c.bufr = bufio.NewReaderSize(conn, 1024)
}

// readerConn returns a net.Conn that drains any bytes already buffered
// in bufr before reading from the underlying connection. Use this when
// handing the connection to another protocol (for example TLS) so that
// peeked/prefetched bytes are not lost.
func (c *ClientConn) readerConn() net.Conn {
	if c.bufr != nil && c.bufr.Buffered() > 0 {
		return &bufConn{Conn: c.Conn, r: c.bufr}
	}
	return c.Conn
}

func (c *ClientConn) logf(format string, args ...interface{}) {
	if c.log != nil {
		c.log.Printf(format, args...)
		return
	}
	log.Printf(format, args...)
}

// Close a connection to a VNC server.
func (c *ClientConn) Close() error {
	if c.log != nil {
		c.log.Println("VNC Client connection closed.")
	}
	c.connTerminated = true
	return c.Conn.Close()
}

// DesktopName returns the server provided desktop name.
func (c *ClientConn) DesktopName() string {
	return c.desktopName
}

// setDesktopName stores the server provided desktop name.
func (c *ClientConn) setDesktopName(name string) {
	if c.log != nil {
		c.log.Printf("desktopName: %s\n", name)
	}
	c.desktopName = name
}

// Encodings returns the server provided encodings.
func (c *ClientConn) Encodings() Encodings {
	return c.encodings
}

// FramebufferHeight returns the server provided framebuffer height.
func (c *ClientConn) FramebufferHeight() uint16 {
	return c.fbHeight
}

// setFramebufferHeight stores the server provided framebuffer height.
func (c *ClientConn) setFramebufferHeight(height uint16) {
	if c.log != nil {
		c.log.Printf("height: %d", height)
	}
	c.fbHeight = height
}

// FramebufferWidth returns the server provided framebuffer width.
func (c *ClientConn) FramebufferWidth() uint16 {
	return c.fbWidth
}

// setFramebufferWidth stores the server provided framebuffer width.
func (c *ClientConn) setFramebufferWidth(width uint16) {
	if c.log != nil {
		c.log.Printf("width: %d", width)
	}
	c.fbWidth = width
}

// ListenAndHandle listens to a VNC server and handles server messages.
func (c *ClientConn) ListenAndHandle() error {
	if c.config.ServerMessages == nil {
		return NewVNCError("Client config error: ServerMessages undefined")
	}
	serverMessages := make(map[messages.ServerMessage]ServerMessage)
	for _, m := range c.config.ServerMessages {
		serverMessages[m.Type()] = m
	}

	for {
		var messageType messages.ServerMessage
		if err := c.receive(&messageType); err != nil {
			if !c.connTerminated {
				c.logf("error: reading from server: %v", err)
			}
			return err
		}
		if c.log != nil {
			c.log.Printf("message-type: %s", messageType)
		}

		msg, ok := serverMessages[messageType]
		if !ok {
			err := NewVNCError(fmt.Sprintf("unsupported message-type: %v", messageType))
			c.logf("%v", err)
			return err
		}

		parsedMsg, err := msg.Read(c)
		if err != nil {
			c.logf("error parsing message; %v", err)
			return err
		}

		if c.config.ServerMessageCh == nil {
			continue
		}

		c.config.ServerMessageCh <- parsedMsg
	}
}

// receive a packet from the network.
func (c *ClientConn) receive(data interface{}) error {
	if err := binary.Read(c.bufr, binary.BigEndian, data); err != nil {
		return err
	}
	c.metrics["bytes-received"].Adjust(int64(binary.Size(data)))
	return nil
}

// receiveN receives N packets from the network.
func (c *ClientConn) receiveN(data interface{}, n int) error {
	if n == 0 {
		return nil
	}

	switch data := data.(type) {
	case *[]uint8:
		var v uint8
		for i := 0; i < n; i++ {
			if err := binary.Read(c.bufr, binary.BigEndian, &v); err != nil {
				return err
			}
			*data = append(*data, v)
		}
		c.metrics["bytes-received"].Adjust(int64(n))
	case *[]int32:
		var v int32
		for i := 0; i < n; i++ {
			if err := binary.Read(c.bufr, binary.BigEndian, &v); err != nil {
				return err
			}
			*data = append(*data, v)
		}
		c.metrics["bytes-received"].Adjust(int64(n) * 4)
	case *[]uint32:
		var v uint32
		for i := 0; i < n; i++ {
			if err := binary.Read(c.bufr, binary.BigEndian, &v); err != nil {
				return err
			}
			*data = append(*data, v)
		}
		c.metrics["bytes-received"].Adjust(int64(n) * 4)
	case *bytes.Buffer:
		var v byte
		for i := 0; i < n; i++ {
			if err := binary.Read(c.bufr, binary.BigEndian, &v); err != nil {
				return err
			}
			data.WriteByte(v)
		}
		c.metrics["bytes-received"].Adjust(int64(n))
	default:
		return NewVNCError(fmt.Sprintf("unrecognized data type %v", reflect.TypeOf(data)))
	}
	return nil
}

// send a packet to the network.
func (c *ClientConn) send(data interface{}) error {
	if err := binary.Write(c.Conn, binary.BigEndian, data); err != nil {
		return err
	}

	c.metrics["bytes-sent"].Adjust(int64(binary.Size(data)))
	return nil
}

// sendN sends N packets to the network.
// func (c *ClientConn) sendN(data interface{}, n int) error {
// 	var buf bytes.Buffer
// 	switch data := data.(type) {
// 	case []uint8:
// 		for _, d := range data {
// 			if err := binary.Write(&buf, binary.BigEndian, &d); err != nil {
// 				return err
// 			}
// 		}
// 	case []int32:
// 		for _, d := range data {
// 			if err := binary.Write(&buf, binary.BigEndian, &d); err != nil {
// 				return err
// 			}
// 		}
// 	default:
// 		return NewVNCError(fmt.Sprintf("unable to send data; unrecognized data type %v", reflect.TypeOf(data)))
// 	}
// 	if err := binary.Write(c.c, binary.BigEndian, buf.Bytes()); err != nil {
// 		return err
// 	}
// 	c.metrics["bytes-sent"].Adjust(int64(binary.Size(data)))
// 	return nil
// }

func (c *ClientConn) processContext(ctx context.Context) error {
	if mpv := ctx.Value("vnc_max_proto_version"); mpv != nil && mpv != "" {
		c.logf("vnc_max_proto_version: %v", mpv)
		vers := []string{"3.3", "3.7", "3.8"}
		valid := false
		for _, v := range vers {
			if mpv == v {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("invalid max protocol version %v; supported versions are %v", mpv, vers)
		}
	}

	return nil
}

func (c *ClientConn) DebugMetrics() {
	log.Println("Metrics:")
	for name, metric := range c.metrics {
		log.Printf("  %v: %v", name, metric.Value())
	}
}
