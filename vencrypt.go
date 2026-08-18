package vnc

import (
	"crypto/tls"
	"fmt"
)

// VeNCrypt 0.2 sub-types. See docs/vencrypt.md.
const (
	veNCryptFailure   = uint32(0)
	veNCryptPlain     = uint32(256)
	veNCryptTLSNone   = uint32(257)
	veNCryptTLSVnc    = uint32(258)
	veNCryptTLSPlain  = uint32(259)
	veNCryptX509None  = uint32(260)
	veNCryptX509Vnc   = uint32(261)
	veNCryptX509Plain = uint32(262)
)

// ClientAuthVeNCryptAuth implements VeNCrypt (security type 19).
// Only TLS/X.509 sub-types that wrap None or VNC authentication are supported.
type ClientAuthVeNCryptAuth struct{}

func (auth *ClientAuthVeNCryptAuth) SecurityType() uint8 {
	return secTypeVeNCrypt
}

func (auth *ClientAuthVeNCryptAuth) Handshake(c *ClientConn) error {
	var vencVersion [2]uint8
	if err := c.receive(&vencVersion); err != nil {
		return err
	}

	// Advertise 0.2, or 0.0 if the server cannot speak a version we support.
	if vencVersion[0] != 0 || vencVersion[1] < 2 {
		_ = c.send([2]uint8{0, 0})
		return fmt.Errorf("unsupported VeNCrypt version %d.%d", vencVersion[0], vencVersion[1])
	}
	if err := c.send([2]uint8{0, 2}); err != nil {
		return err
	}

	var isAccepted uint8
	if err := c.receive(&isAccepted); err != nil {
		return err
	}
	if isAccepted != 0 {
		return fmt.Errorf("server rejected VeNCrypt version 0.2")
	}

	var subtypesCnt uint8
	if err := c.receive(&subtypesCnt); err != nil {
		return err
	}
	if subtypesCnt == 0 {
		return fmt.Errorf("server offered no VeNCrypt sub-types")
	}

	var subauthTypes []uint32
	if err := c.receiveN(&subauthTypes, int(subtypesCnt)); err != nil {
		return err
	}
	if c.log != nil {
		c.log.Printf("vencAccSubAuthTypes %v", subauthTypes)
	}

	chosen := chooseVeNCryptSubType(subauthTypes)
	if chosen == veNCryptFailure {
		_ = c.send(uint32(0))
		return fmt.Errorf("no supported VeNCrypt sub-type; server offered %v", subauthTypes)
	}
	if err := c.send(chosen); err != nil {
		return err
	}

	// Implementations (including noVNC) send a U8 after the chosen sub-type:
	// 1 = accepted, 0 = rejected.
	isAccepted = 0
	if err := c.receive(&isAccepted); err != nil {
		return err
	}
	if isAccepted != 1 {
		return fmt.Errorf("server rejected VeNCrypt sub-type %d", chosen)
	}

	tlsCfg := &tls.Config{InsecureSkipVerify: true}
	tconn := tls.Client(c.readerConn(), tlsCfg)
	if err := tconn.Handshake(); err != nil {
		return fmt.Errorf("VeNCrypt TLS handshake failed: %w", err)
	}
	c.setConn(tconn)

	switch chosen {
	case veNCryptTLSNone, veNCryptX509None:
		// Inner authentication is None. Keep secType as VeNCrypt so that
		// SecurityResult is still read (it is not RFB type None).
		return nil
	case veNCryptTLSVnc, veNCryptX509Vnc:
		cauth := auth.innerVNCAuth(c)
		c.config.secType = cauth.SecurityType()
		if err := cauth.Handshake(c); err != nil {
			return err
		}
		return nil
	default:
		return fmt.Errorf("unsupported VeNCrypt sub-type %d", chosen)
	}
}

func (auth *ClientAuthVeNCryptAuth) innerVNCAuth(c *ClientConn) ClientAuth {
	if c.config != nil {
		for _, a := range c.config.Auth {
			if a != nil && a.SecurityType() == secTypeVNCAuth {
				return a
			}
		}
		return &ClientAuthVNC{Password: c.config.Password}
	}
	return &ClientAuthVNC{}
}

func chooseVeNCryptSubType(offered []uint32) uint32 {
	preferred := []uint32{
		veNCryptX509Vnc,
		veNCryptTLSVnc,
		veNCryptX509None,
		veNCryptTLSNone,
	}
	have := make(map[uint32]struct{}, len(offered))
	for _, t := range offered {
		have[t] = struct{}{}
	}
	for _, t := range preferred {
		if _, ok := have[t]; ok {
			return t
		}
	}
	return veNCryptFailure
}
