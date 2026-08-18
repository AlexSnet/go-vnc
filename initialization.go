// Implementation of RFC 6143 §7.3 Initialization Messages.

package vnc

import (
	"encoding/binary"
	"io"

	"github.com/alexsnet/go-vnc/rfbflags"
)

// clientInit implements §7.3.1 ClientInit.
func (c *ClientConn) clientInit() error {
	sharedFlag := rfbflags.BoolToRFBFlag(!c.config.Exclusive)
	if err := c.send(sharedFlag); err != nil {
		return err
	}
	return nil
}

// discardOptionalVenuePadding skips the 4 zero bytes that some Avid VENUE
// servers send after ClientInit, before ServerInit. The peek is performed
// here (on the server stream) so ClientInit does not try to read from the
// connection after writing.
func (c *ClientConn) discardOptionalVenuePadding() error {
	dat, err := c.bufr.Peek(4)
	if err != nil {
		return err
	}
	if binary.BigEndian.Uint32(dat) != 0 {
		return nil
	}
	_, err = c.bufr.Discard(4)
	return err
}

// ServerInit message sent after server receives a ClientInit message.
// https://tools.ietf.org/html/rfc6143#section-7.3.2
type ServerInit struct {
	FBWidth, FBHeight uint16
	PixelFormat       PixelFormat
	NameLength        uint32
	// Name is of variable length, and must be read separately.
}

const serverInitLen = 24 // Not including Name.

// Verify that interfaces are honored.
var _ Unmarshaler = (*ServerInit)(nil)

// Read implements
func (m *ServerInit) Read(r io.Reader) error {
	buf := make([]byte, serverInitLen)
	if _, err := io.ReadAtLeast(r, buf, serverInitLen); err != nil {
		return err
	}
	return m.Unmarshal(buf)
}

func (m *ServerInit) Unmarshal(data []byte) error {
	buf := NewBuffer(data)
	var msg ServerInit
	if err := buf.Read(&msg); err != nil {
		return err
	}
	*m = msg
	return nil
}

// serverInit implements §7.3.2 ServerInit.
func (c *ClientConn) serverInit() error {
	if err := c.discardOptionalVenuePadding(); err != nil {
		return Errorf("failure reading ServerInit message; %v", err)
	}

	var msg ServerInit
	if err := c.receive(&msg); err != nil {
		return Errorf("failure reading ServerInit message; %v", err)
	}

	c.setFramebufferWidth(msg.FBWidth)
	c.setFramebufferHeight(msg.FBHeight)
	c.pixelFormat = msg.PixelFormat

	if msg.NameLength > maxReasonLen {
		return NewVNCError("desktop name is too long")
	}
	name := make([]uint8, msg.NameLength)
	if err := c.receive(&name); err != nil {
		return err
	}
	c.setDesktopName(string(name))

	return nil
}
