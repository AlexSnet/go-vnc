package vnc

import (
	"io"
	"testing"
)

func TestClientInit(t *testing.T) {
	tests := []struct {
		exclusive bool
		shared    uint8
	}{
		{true, 0},
		{false, 1},
	}

	mockConn := &MockConn{}
	conn := NewClientConn(mockConn, &ClientConfig{})

	for _, tt := range tests {
		mockConn.Reset()

		// Send client initialization.
		conn.config.Exclusive = tt.exclusive
		if err := conn.clientInit(); err != nil {
			t.Fatalf("unexpected error; %s", err)
		}

		// Validate server reception.
		var shared uint8
		if err := conn.receive(&shared); err != nil {
			t.Errorf("error receiving client init; %s", err)
			continue
		}
		if got, want := shared, tt.shared; got != want {
			t.Errorf("incorrect shared-flag: got = %d, want = %d", got, want)
			continue
		}

		// Ensure nothing extra was sent by client.
		var buf []byte
		if err := conn.receiveN(&buf, 1024); err != io.EOF {
			t.Errorf("expected EOF; %s", err)
			continue
		}
	}
}

func TestServerInit(t *testing.T) {
	const (
		none = iota
		fbw
		fbh
		pf
		dn
	)
	tests := []struct {
		eof               int
		fbWidth, fbHeight uint16
		pixelFormat       PixelFormat
		desktopName       string
	}{
		// Valid protocol.
		{dn, 100, 200, NewPixelFormat(16), "foo"},
		// Invalid protocol (missing fields).
		{eof: none},
		{eof: fbw, fbWidth: 1},
		{eof: fbh, fbWidth: 2, fbHeight: 1},
		{eof: pf, fbWidth: 3, fbHeight: 2, pixelFormat: NewPixelFormat(16)},
	}

	mockConn := &MockConn{}
	conn := NewClientConn(mockConn, &ClientConfig{})

	for i, tt := range tests {
		mockConn.Reset()
		if tt.eof >= fbw {
			if err := conn.send(tt.fbWidth); err != nil {
				t.Fatal(err)
			}
		}
		if tt.eof >= fbh {
			if err := conn.send(tt.fbHeight); err != nil {
				t.Fatal(err)
			}
		}
		if tt.eof >= pf {
			pfBytes, err := tt.pixelFormat.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			if err := conn.send(pfBytes); err != nil {
				t.Fatal(err)
			}
		}
		if tt.eof >= dn {
			if err := conn.send(uint32(len(tt.desktopName))); err != nil {
				t.Fatal(err)
			}
			if err := conn.send([]byte(tt.desktopName)); err != nil {
				t.Fatal(err)
			}
		}

		// Validate server message handling.
		err := conn.serverInit()
		if tt.eof < dn && err == nil {
			t.Fatalf("%v: expected error", i)
		}
		if tt.eof < dn {
			// The protocol was incomplete; no point in checking values.
			continue
		}
		if err != nil {
			t.Fatalf("%v: unexpected error %v", i, err)
		}
		if conn.fbWidth != tt.fbWidth {
			t.Errorf("FramebufferWidth: got = %v, want = %v", conn.fbWidth, tt.fbWidth)
		}
		if conn.fbHeight != tt.fbHeight {
			t.Errorf("FramebufferHeight: got = %v, want = %v", conn.fbHeight, tt.fbHeight)
		}
		if !equalPixelFormat(conn.pixelFormat, tt.pixelFormat) {
			t.Errorf("PixelFormat: got = %v, want = %v", conn.pixelFormat, tt.pixelFormat)
		}
		if conn.DesktopName() != tt.desktopName {
			t.Errorf("DesktopName: got = %v, want = %v", conn.DesktopName(), tt.desktopName)
		}
	}
}

func TestServerInit_VenuePadding(t *testing.T) {
	mockConn := &MockConn{}
	conn := NewClientConn(mockConn, &ClientConfig{})

	if err := conn.send(uint32(0)); err != nil {
		t.Fatal(err)
	}
	if err := conn.send(uint16(320)); err != nil {
		t.Fatal(err)
	}
	if err := conn.send(uint16(240)); err != nil {
		t.Fatal(err)
	}
	pf := NewPixelFormat(16)
	pfBytes, err := pf.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.send(pfBytes); err != nil {
		t.Fatal(err)
	}
	name := "venue"
	if err := conn.send(uint32(len(name))); err != nil {
		t.Fatal(err)
	}
	if err := conn.send([]byte(name)); err != nil {
		t.Fatal(err)
	}

	if err := conn.serverInit(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := conn.FramebufferWidth(), uint16(320); got != want {
		t.Errorf("FramebufferWidth: got = %v, want = %v", got, want)
	}
	if got, want := conn.FramebufferHeight(), uint16(240); got != want {
		t.Errorf("FramebufferHeight: got = %v, want = %v", got, want)
	}
	if got, want := conn.DesktopName(), name; got != want {
		t.Errorf("DesktopName: got = %v, want = %v", got, want)
	}
}
