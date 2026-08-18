package vnc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestChooseVeNCryptSubType(t *testing.T) {
	tests := []struct {
		offered []uint32
		want    uint32
	}{
		{[]uint32{veNCryptPlain}, veNCryptFailure},
		{[]uint32{veNCryptTLSNone, veNCryptX509Vnc}, veNCryptX509Vnc},
		{[]uint32{veNCryptTLSVnc, veNCryptTLSNone}, veNCryptTLSVnc},
		{[]uint32{veNCryptTLSNone}, veNCryptTLSNone},
		{[]uint32{veNCryptPlain, veNCryptX509None}, veNCryptX509None},
	}
	for i, tt := range tests {
		if got := chooseVeNCryptSubType(tt.offered); got != tt.want {
			t.Errorf("%d: chooseVeNCryptSubType(%v) = %d, want %d", i, tt.offered, got, tt.want)
		}
	}
}

func TestVeNCryptHandshake_UnsupportedVersion(t *testing.T) {
	mockConn := &MockConn{}
	conn := NewClientConn(mockConn, NewClientConfig("secret"))

	if err := conn.send([2]uint8{0, 1}); err != nil {
		t.Fatal(err)
	}
	err := (&ClientAuthVeNCryptAuth{}).Handshake(conn)
	if err == nil {
		t.Fatal("expected error for VeNCrypt 0.1")
	}

	var vers [2]uint8
	if err := conn.receive(&vers); err != nil {
		t.Fatal(err)
	}
	if vers != [2]uint8{0, 0} {
		t.Errorf("expected client to send 0.0, got %v", vers)
	}
}

func TestVeNCryptHandshake_NoMatchingSubType(t *testing.T) {
	mockConn := &MockConn{}
	conn := NewClientConn(mockConn, NewClientConfig("secret"))

	if err := conn.send([2]uint8{0, 2}); err != nil {
		t.Fatal(err)
	}
	if err := conn.send(uint8(0)); err != nil { // version accepted
		t.Fatal(err)
	}
	if err := conn.send(uint8(1)); err != nil {
		t.Fatal(err)
	}
	if err := conn.send(uint32(veNCryptPlain)); err != nil {
		t.Fatal(err)
	}

	err := (&ClientAuthVeNCryptAuth{}).Handshake(conn)
	if err == nil {
		t.Fatal("expected error when only Plain is offered")
	}

	var vers [2]uint8
	if err := conn.receive(&vers); err != nil {
		t.Fatal(err)
	}
	if vers != [2]uint8{0, 2} {
		t.Errorf("expected client to send 0.2, got %v", vers)
	}
	var chosen uint32
	if err := conn.receive(&chosen); err != nil {
		t.Fatal(err)
	}
	if chosen != 0 {
		t.Errorf("expected client to send sub-type 0, got %d", chosen)
	}
}

func TestVeNCryptHandshake_X509Vnc(t *testing.T) {
	cert, err := testTLSCertificate()
	if err != nil {
		t.Fatal(err)
	}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	challenge := vncAuthChallenge{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	password := "secret"
	done := make(chan error, 1)

	go func() {
		defer serverConn.Close()
		sc := NewClientConn(serverConn, &ClientConfig{})

		// Version 0.2, accept, one sub-type (X509Vnc), accept sub-type.
		if err := sc.send([2]uint8{0, 2}); err != nil {
			done <- err
			return
		}
		var clientVer [2]uint8
		if err := sc.receive(&clientVer); err != nil {
			done <- err
			return
		}
		if clientVer != [2]uint8{0, 2} {
			done <- errString("client version mismatch")
			return
		}
		if err := sc.send(uint8(0)); err != nil {
			done <- err
			return
		}
		if err := sc.send(uint8(1)); err != nil {
			done <- err
			return
		}
		if err := sc.send(uint32(veNCryptX509Vnc)); err != nil {
			done <- err
			return
		}
		var chosen uint32
		if err := sc.receive(&chosen); err != nil {
			done <- err
			return
		}
		if chosen != veNCryptX509Vnc {
			done <- errString("unexpected sub-type")
			return
		}
		if err := sc.send(uint8(1)); err != nil {
			done <- err
			return
		}

		tlsSrv := tls.Server(sc.readerConn(), &tls.Config{Certificates: []tls.Certificate{cert}})
		if err := tlsSrv.Handshake(); err != nil {
			done <- err
			return
		}
		sc.setConn(tlsSrv)

		if err := sc.send(challenge); err != nil {
			done <- err
			return
		}
		var resp vncAuthChallenge
		if err := sc.receive(&resp); err != nil {
			done <- err
			return
		}
		auth := ClientAuthVNC{Password: password}
		want := challenge
		if err := auth.encode(&want); err != nil {
			done <- err
			return
		}
		if resp != want {
			done <- errString("VNC auth response mismatch")
			return
		}
		done <- nil
	}()

	cc := NewClientConn(clientConn, NewClientConfig(password))
	if err := (&ClientAuthVeNCryptAuth{}).Handshake(cc); err != nil {
		t.Fatalf("client handshake: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("server handshake: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server handshake")
	}
}

type errString string

func (e errString) Error() string { return string(e) }

func testTLSCertificate() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "go-vnc-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return tls.X509KeyPair(certPEM, keyPEM)
}
