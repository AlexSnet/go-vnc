package vnc

import (
	"encoding/binary"
	"io"
	"reflect"
	"testing"

	"context"
)

func TestParseProtocolVersion(t *testing.T) {
	tests := []struct {
		proto        []byte
		major, minor uint
		ok           bool
	}{
		//-- Valid ProtocolVersion messages.
		// RFB 003.008\n
		{[]byte{82, 70, 66, 32, 48, 48, 51, 46, 48, 48, 56, 10}, 3, 8, true},
		// RFB 003.889\n -- OS X 10.10.3
		{[]byte{82, 70, 66, 32, 48, 48, 51, 46, 56, 56, 57, 10}, 3, 889, true},
		// RFB 000.0000\n
		{[]byte{82, 70, 66, 32, 48, 48, 48, 46, 48, 48, 48, 10}, 0, 0, true},
		// RFB 003.006\n -- Avid VENUE
		{[]byte{0x52, 0x46, 0x42, 0x20, 0x30, 0x30, 0x33, 0x2e, 0x30, 0x30, 0x36, 0x0a}, 3, 6, true},
		//-- Invalid messages.
		// RFB 3.8\n -- too short; not zero padded
		{[]byte{82, 70, 66, 32, 51, 46, 56, 10}, 0, 0, false},
		// RFB\n -- too short
		{[]byte{82, 70, 66, 10}, 0, 0, false},
		// (empty) -- too short
		{[]byte{}, 0, 0, false},
	}

	for i, tt := range tests {
		major, minor, err := parseProtocolVersion(tt.proto)
		if err == nil && !tt.ok {
			t.Errorf("%d: expected error", i)
			continue
		}
		if err != nil && tt.ok {
			t.Errorf("%d: unexpected error %v", i, err)
			continue
		}
		if !tt.ok {
			continue
		}
		// TODO(kward): validate VNCError thrown.
		if got, want := major, tt.major; got != want {
			t.Errorf("%d: incorrect major version; got = %v, want = %v", i, got, want)
			continue
		}
		if got, want := minor, tt.minor; got != want {
			t.Errorf("%d: incorrect minor version; got = %v, want = %v", i, got, want)
			continue
		}
	}
}

func TestProtocolVersionHandshake(t *testing.T) {
	tests := []struct {
		server string
		client string
		ok     bool
	}{
		// Supported versions.
		{"RFB 003.003\n", "RFB 003.003\n", true},
		{"RFB 003.006\n", "RFB 003.003\n", true},
		{"RFB 003.007\n", "RFB 003.007\n", true},
		{"RFB 003.008\n", "RFB 003.008\n", true},
		{"RFB 003.389\n", "RFB 003.008\n", true},
		// Unsupported versions.
		{server: "RFB 002.009\n", ok: false},
	}

	mockConn := &MockConn{}
	conn := NewClientConn(mockConn, &ClientConfig{})

	for _, tt := range tests {
		mockConn.Reset()

		// Send server version.
		if err := conn.send([]byte(tt.server)); err != nil {
			t.Fatal(err)
		}

		// Perform protocol version handshake.
		err := conn.protocolVersionHandshake(context.Background())
		if err == nil && !tt.ok {
			t.Fatalf("protocolVersionHandshake() expected error for server protocol version %v", tt.server)
		}
		if err != nil {
			if verr, ok := err.(*VNCError); !ok {
				t.Errorf("protocolVersionHandshake() unexpected %v error: %v", reflect.TypeOf(err), verr)
			}
		}

		// Validate client response.
		var client [pvLen]byte
		err = conn.receive(&client)
		if err == nil && !tt.ok {
			t.Fatalf("protocolVersionHandshake() unexpected error: %v", err)
		}
		if string(client[:]) != tt.client && tt.ok {
			t.Errorf("protocolVersionHandshake() client version: got = %v, want = %v", string(client[:]), tt.client)
		}

		// Ensure nothing extra was sent.
		var buf []byte
		if err := conn.receiveN(&buf, 1024); err != io.EOF {
			t.Errorf("expected EOF; got = %v", err)
		}
	}
}

func writeVNCAuthChallenge(w io.Writer) error {
	var ch vncAuthChallenge = vncAuthChallenge{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	return binary.Write(w, binary.BigEndian, ch)
}

func TestSecurityHandshake33(t *testing.T) {
	tests := []struct {
		secType    uint32 // 3.3 uses uint32, but 3.8 uses uint8. Unified on 3.8.
		ok         bool
		reason     string
		recv, sent uint64
	}{
		//-- Supported security types. --
		// Server supports None.
		{uint32(secTypeNone), true, "", 4, 0},
		// Server supports VNCAuth.
		{uint32(secTypeVNCAuth), true, "", 20, 16},
		//-- Unsupported security types. --
		{
			secType: uint32(secTypeInvalid),
			reason:  "some reason"},
		{secType: 255},
	}

	mockConn := &MockConn{}
	conn := NewClientConn(mockConn, NewClientConfig("."))
	conn.protocolVersion = PROTO_VERS_3_3

	for i, tt := range tests {
		mockConn.Reset()

		// Send server message.
		if err := conn.send(tt.secType); err != nil {
			t.Fatalf("error sending security-type: %v", err)
		}
		if len(tt.reason) > 0 {
			if err := conn.send(uint32(len(tt.reason))); err != nil {
				t.Fatalf("error sending reason-length: %v", err)
			}
			if err := conn.send([]byte(tt.reason)); err != nil {
				t.Fatalf("error sending reason-string: %v", err)
			}
		}
		if tt.secType == uint32(secTypeVNCAuth) {
			if err := writeVNCAuthChallenge(conn.Conn); err != nil {
				t.Fatalf("error sending VNCAuth challenge: %v", err)
			}
		}

		// Perform security handshake.
		for _, m := range conn.metrics {
			m.Reset()
		}
		err := conn.securityHandshake()
		if err == nil && !tt.ok {
			t.Fatalf("%v: expected error for security-type %v", i, tt.secType)
		}
		if err != nil {
			if verr, ok := err.(*VNCError); !ok {
				t.Errorf("%v: unexpected %v error: %v", i, reflect.TypeOf(err), verr)
			}
		}
		if !tt.ok {
			continue
		}

		// Check bytes sent/received.
		if got, want := conn.metrics["bytes-received"].Value(), tt.recv; got != want {
			t.Errorf("%v: incorrect number of bytes received; got = %v, want = %v", i, got, want)
		}
		if got, want := conn.metrics["bytes-sent"].Value(), tt.sent; got != want {
			t.Errorf("%v: incorrect number of bytes sent; got = %v, want = %v", i, got, want)
		}

		// Validate client response.
		if tt.secType == uint32(secTypeVNCAuth) {
			var ch vncAuthChallenge
			if err := conn.receive(&ch); err != nil {
				t.Fatalf("%v: error reading VNCAuth response: %v", i, err)
			}
		}

		// Ensure nothing extra was sent by client.
		var buf []byte
		if err := conn.receiveN(&buf, 1024); err != io.EOF {
			t.Errorf("%v, expected EOF; got = %v", i, err)
		}
	}
}

func TestSecurityHandshake38(t *testing.T) {
	tests := []struct {
		secTypes   []uint8
		client     []ClientAuth
		secType    uint8
		ok         bool
		reason     string
		recv, sent uint64
	}{
		//-- Supported security types --
		// Server and client support None.
		{[]uint8{secTypeNone}, []ClientAuth{&ClientAuthNone{}}, secTypeNone, true, "", 2, 1},
		// Server and client support VNCAuth.
		{[]uint8{secTypeVNCAuth}, []ClientAuth{&ClientAuthVNC{"."}}, secTypeVNCAuth, true, "", 18, 17},
		// Server and client both support VNCAuth and None.
		{[]uint8{secTypeVNCAuth, secTypeNone}, []ClientAuth{&ClientAuthVNC{"."}, &ClientAuthNone{}}, secTypeVNCAuth, true, "", 19, 17},
		// Server supports unknown #255, VNCAuth and None.
		{[]uint8{255, secTypeVNCAuth, secTypeNone}, []ClientAuth{&ClientAuthVNC{"."}, &ClientAuthNone{}}, secTypeVNCAuth, true, "", 20, 17},
		{ // No security types provided.
			secTypes: []uint8{},
			client:   []ClientAuth{},
			secType:  secTypeInvalid,
			reason:   "no security types"},
		//-- Unsupported security types --
		{ // Server provided no valid security types.
			secTypes: []uint8{secTypeInvalid},
			client:   []ClientAuth{},
			secType:  secTypeInvalid,
			reason:   "invalid security type"},
		{ // Client and server don't support same security types.
			secTypes: []uint8{secTypeVNCAuth},
			client:   []ClientAuth{&ClientAuthNone{}},
			secType:  secTypeInvalid},
		{ // Server supports only unknown #255.
			secTypes: []uint8{255},
			client:   []ClientAuth{&ClientAuthNone{}},
			secType:  secTypeInvalid},
	}

	mockConn := &MockConn{}
	conn := NewClientConn(mockConn, &ClientConfig{})
	conn.protocolVersion = PROTO_VERS_3_8

	for i, tt := range tests {
		mockConn.Reset()

		// Send server message.
		if err := conn.send(uint8(len(tt.secTypes))); err != nil {
			t.Fatal(err)
		}
		if err := conn.send(tt.secTypes); err != nil {
			t.Fatal(err)
		}
		if !tt.ok {
			if err := conn.send(uint32(len(tt.reason))); err != nil {
				t.Fatal(err)
			}
			if err := conn.send([]byte(tt.reason)); err != nil {
				t.Fatal(err)
			}
		}
		if tt.secType == secTypeVNCAuth {
			if err := writeVNCAuthChallenge(conn.Conn); err != nil {
				t.Fatalf("error sending VNCAuth challenge: %s", err)
			}
		}
		conn.config.Auth = tt.client

		// Perform Security Handshake.
		for _, m := range conn.metrics {
			m.Reset()
		}
		err := conn.securityHandshake()
		if err != nil && tt.ok {
			if verr, ok := err.(*VNCError); !ok {
				t.Fatalf("%d: unexpected %v error: %s", i, reflect.TypeOf(err), verr)
			}
		}
		if err == nil && !tt.ok {
			t.Fatalf("%d: expected error for server auth %v", i, tt.secTypes)
		}
		if !tt.ok {
			continue
		}

		// Check bytes sent/received.
		if got, want := conn.metrics["bytes-received"].Value(), tt.recv; got != want {
			t.Errorf("%d: incorrect number of bytes received; got = %v, want = %v", i, got, want)
		}
		if got, want := conn.metrics["bytes-sent"].Value(), tt.sent; got != want {
			t.Errorf("%d: incorrect number of bytes sent; got = %v, want = %v", i, got, want)
		}

		// Validate client response.
		var secType uint8
		err = conn.receive(&secType)
		if got, want := secType, tt.secType; got != want {
			t.Errorf("%d: incorrect security-type; got = %v, want = %v", i, got, want)
		}
		if got, want := conn.config.secType, secType; got != want {
			t.Errorf("%d: secType not stored; got = %v, want = %v", i, got, want)
		}
		if tt.secType == secTypeVNCAuth {
			var ch vncAuthChallenge
			if err := conn.receive(&ch); err != nil {
				t.Fatalf("%d: error reading VNCAuth response: %s", i, err)
			}
		}

		// Ensure nothing extra was sent by client.
		var buf []byte
		if err := conn.receiveN(&buf, 1024); err != io.EOF {
			t.Errorf("%v: expected EOF; got = %v", i, err)
		}

	}
}

func TestSecurityResultHandshake(t *testing.T) {
	tests := []struct {
		proto  string
		sec    uint8
		result uint32
		ok     bool
		reason string
		errstr string
	}{
		{PROTO_VERS_3_8, secTypeVNCAuth, 0, true, "", ""},
		{PROTO_VERS_3_8, secTypeVNCAuth, 1, false, "SecurityResult error", "SecurityResult handshake failed: SecurityResult error"},
		{PROTO_VERS_3_8, secTypeNone, 0, true, "", ""},
		{PROTO_VERS_3_3, secTypeNone, 0, true, "", ""},
		{PROTO_VERS_3_7, secTypeVNCAuth, 1, false, "", "SecurityResult handshake failed"},
	}

	mockConn := &MockConn{}
	conn := NewClientConn(mockConn, &ClientConfig{})

	for i, tt := range tests {
		mockConn.Reset()
		conn.protocolVersion = tt.proto
		conn.config.secType = tt.sec

		// RFB 3.3 + None does not send SecurityResult at all.
		if !(tt.proto == PROTO_VERS_3_3 && tt.sec == secTypeNone) {
			if err := conn.send(tt.result); err != nil {
				t.Fatal(err)
			}
			if tt.reason != "" {
				if err := conn.send(uint32(len(tt.reason))); err != nil {
					t.Fatal(err)
				}
				if err := conn.send([]byte(tt.reason)); err != nil {
					t.Fatal(err)
				}
			}
		}

		err := conn.securityResultHandshake()
		if err == nil && !tt.ok {
			t.Fatalf("%d: expected error for result %v", i, tt.result)
		}
		if err != nil && tt.ok {
			t.Fatalf("%d: unexpected error: %v", i, err)
		}
		if err != nil {
			if verr, ok := err.(*VNCError); !ok {
				t.Errorf("%d: unexpected %v error: %v", i, reflect.TypeOf(err), verr)
			}
			if got, want := err.Error(), tt.errstr; got != want {
				t.Errorf("%d: incorrect error; got = %q, want = %q", i, got, want)
			}
		}
	}
}

func TestProtocolVersionHandshakeMaxVersion(t *testing.T) {
	mockConn := &MockConn{}
	conn := NewClientConn(mockConn, &ClientConfig{})

	// Server offers 3.8, caller caps at 3.3.
	mockConn.Reset()
	if err := conn.send([]byte(PROTO_VERS_3_8)); err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), "vnc_max_proto_version", "3.3")
	if err := conn.protocolVersionHandshake(ctx); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var client [pvLen]byte
	if err := conn.receive(&client); err != nil {
		t.Fatal(err)
	}
	if got, want := string(client[:]), PROTO_VERS_3_3; got != want {
		t.Errorf("capped version; got = %q, want = %q", got, want)
	}

	// Server offers 3.3; max 3.8 must not upgrade past the server.
	mockConn.Reset()
	if err := conn.send([]byte(PROTO_VERS_3_3)); err != nil {
		t.Fatal(err)
	}
	ctx = context.WithValue(context.Background(), "vnc_max_proto_version", "3.8")
	if err := conn.protocolVersionHandshake(ctx); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := conn.receive(&client); err != nil {
		t.Fatal(err)
	}
	if got, want := string(client[:]), PROTO_VERS_3_3; got != want {
		t.Errorf("must not upgrade; got = %q, want = %q", got, want)
	}
}
