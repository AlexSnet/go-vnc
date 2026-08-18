package vnc

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"reflect"
	"testing"

	"context"
)

func newMockServer(t *testing.T, version string) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("error listening: %s", err)
	}

	go func() {

		defer ln.Close()
		c, err := ln.Accept()
		if err != nil {
			// t.Fatalf("error accepting conn: %s", err)
			panic(err)
		}
		defer c.Close()

		_, err = c.Write([]byte(fmt.Sprintf("RFB %s\n", version)))
		if err != nil {
			// t.Fatal("failed writing version")
			panic(err)
		}
	}()

	return ln.Addr().String()
}

func TestLowMajorVersion(t *testing.T) {
	nc, err := net.Dial("tcp", newMockServer(t, "002.009"))
	if err != nil {
		t.Fatalf("error connecting to mock server: %s", err)
	}

	_, err = Connect(context.Background(), nc, &ClientConfig{})
	if err == nil {
		t.Fatal("error expected")
	}
	if err != nil {
		if verr, ok := err.(*VNCError); !ok {
			t.Errorf("Client() unexpected %v error: %v", reflect.TypeOf(err), verr)
		}
	}
}

func TestLowMinorVersion(t *testing.T) {
	nc, err := net.Dial("tcp", newMockServer(t, "003.002"))
	if err != nil {
		t.Fatalf("error connecting to mock server: %s", err)
	}

	_, err = Connect(context.Background(), nc, &ClientConfig{})
	if err == nil {
		t.Fatal("error expected")
	}
	if err != nil {
		if verr, ok := err.(*VNCError); !ok {
			t.Errorf("Client() unexpected %v error: %v", reflect.TypeOf(err), verr)
		}
	}
}

func TestConnectInvalidContext(t *testing.T) {
	mockConn := &MockConn{}
	cfg := NewClientConfig("pw")
	ctx := context.WithValue(context.Background(), "vnc_max_proto_version", "9.9")
	_, err := Connect(ctx, mockConn, cfg)
	if err == nil {
		t.Fatal("expected error for invalid max protocol version")
	}
}

func TestClientConn(t *testing.T) {
	conn := &ClientConn{}

	if got, want := conn.DesktopName(), ""; got != want {
		t.Errorf("DesktopName() failed; got = %v, want = %v", got, want)
	}
	if got, want := conn.FramebufferHeight(), uint16(0); got != want {
		t.Errorf("FramebufferHeight() failed; got = %v, want = %v", got, want)
	}
	if got, want := conn.FramebufferWidth(), uint16(0); got != want {
		t.Errorf("FramebufferWidth() failed; got = %v, want = %v", got, want)
	}
}

func TestReceiveN(t *testing.T) {
	tests := []struct {
		data interface{}
	}{
		{[]uint8{10, 11, 12}},
		{[]int32{20, 21, 22}},
		{[]uint32{40, 41, 42}},
		{bytes.NewBuffer([]byte{30, 31, 32})},
	}

	mockConn := &MockConn{}
	conn := NewClientConn(mockConn, &ClientConfig{})

	for _, tt := range tests {
		mockConn.Reset()

		// Place data in buffer.
		var d interface{}
		switch tt.data.(type) {
		case *bytes.Buffer:
			d = tt.data.(*bytes.Buffer).Bytes()
		default:
			d = tt.data
		}
		if err := binary.Write(conn.Conn, binary.BigEndian, d); err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		// Read data from buffer.
		switch tt.data.(type) {
		case []uint8:
			var data []uint8
			n := len(tt.data.([]uint8))
			if err := conn.receiveN(&data, n); err != nil {
				t.Errorf("error receiving data: %v", err)
			}
			if got, want := len(data), n; got != want {
				t.Errorf("incorrect amount of data received; got = %v, want = %v", got, want)
			}
		case []int32:
			var data []int32
			n := len(tt.data.([]int32))
			if err := conn.receiveN(&data, n); err != nil {
				t.Errorf("error receiving data: %v", err)
			}
			if got, want := len(data), n; got != want {
				t.Errorf("incorrect amount of data received; got = %v, want = %v", got, want)
			}
		case []uint32:
			var data []uint32
			n := len(tt.data.([]uint32))
			if err := conn.receiveN(&data, n); err != nil {
				t.Errorf("error receiving data: %v", err)
			}
			if got, want := len(data), n; got != want {
				t.Errorf("incorrect amount of data received; got = %v, want = %v", got, want)
			}
			if got, want := data, tt.data.([]uint32); !reflect.DeepEqual(got, want) {
				t.Errorf("incorrect data received; got = %v, want = %v", got, want)
			}
		case *bytes.Buffer:
			var data bytes.Buffer
			n := len(tt.data.(*bytes.Buffer).Bytes())
			if err := conn.receiveN(&data, n); err != nil {
				t.Errorf("error receiving data: %v", err)
			}
			if got, want := data.Len(), n; got != want {
				t.Errorf("incorrect amount of data received; got = %v, want = %v", got, want)
			}
		default:
			t.Fatalf("unimplemented for %v", reflect.TypeOf(tt.data))
		}
	}
}
