package vnc

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/alexsnet/go-vnc/go/operators"
	"github.com/alexsnet/go-vnc/rfbflags"
)

const (
	// Shadow the RFBFlag constants.
	RFBFalse = rfbflags.RFBFalse
	RFBTrue  = rfbflags.RFBTrue
)

func TestPixelFormat_Marshal(t *testing.T) {
	tests := []struct {
		pf PixelFormat
		b  []byte
		ok bool
	}{
		//
		// Valid PixelFormats.
		//
		{PixelFormat{BPP: 8, Depth: 8, BigEndian: RFBTrue, TrueColor: RFBFalse},
			[]uint8{8, 8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, true},
		{PixelFormat{BPP: 32, Depth: 24, BigEndian: RFBTrue, TrueColor: RFBTrue,
			RedMax: 255, GreenMax: 255, BlueMax: 255, RedShift: 16, GreenShift: 8, BlueShift: 0},
			[]uint8{32, 24, 1, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0}, true},
		{NewPixelFormat(16),
			[]uint8{16, 16, 1, 1, 255, 255, 255, 255, 255, 255, 0, 4, 8, 0, 0, 0}, true},
		//
		// Invalid PixelFormats.
		//
		// BPP invalid
		{PixelFormat{BPP: 1, Depth: 1, BigEndian: RFBTrue, TrueColor: RFBFalse},
			[]uint8{}, false},
		// Depth invalid
		{PixelFormat{BPP: 8, Depth: 1, BigEndian: RFBTrue, TrueColor: RFBFalse},
			[]uint8{}, false},
		// Depth > BPP (RFC 6143 requires depth <= bits-per-pixel)
		{PixelFormat{BPP: 8, Depth: 16, BigEndian: RFBTrue, TrueColor: RFBFalse},
			[]uint8{}, false},
	}

	for _, tt := range tests {
		pf := tt.pf
		b, err := pf.Marshal()
		if err == nil && !tt.ok {
			t.Error("expected error")
		}
		if err != nil {
			if verr, ok := err.(*VNCError); !ok {
				t.Errorf("unexpected %v error: %v", reflect.TypeOf(err), verr)
			}
		}
		if !tt.ok {
			continue
		}
		if got, want := b, tt.b; !operators.EqualSlicesOfByte(got, want) {
			t.Errorf("invalid pixel-format; got = %v, want = %v", got, want)
		}
	}
}

func TestPixelFormat_Unmarshal(t *testing.T) {
	tests := []struct {
		b  []byte
		pf PixelFormat
		ok bool
	}{
		//
		// Valid PixelFormats.
		//
		{[]uint8{8, 8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			PixelFormat{BPP: 8, Depth: 8, BigEndian: RFBTrue, TrueColor: RFBFalse},
			true},
		{[]uint8{32, 24, 1, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0},
			PixelFormat{
				BPP: 32, Depth: 24,
				BigEndian: RFBTrue, TrueColor: RFBTrue,
				RedMax: 255, GreenMax: 255, BlueMax: 255,
				RedShift: 16, GreenShift: 8, BlueShift: 0},
			true},
		{[]uint8{16, 16, 1, 1, 255, 255, 255, 255, 255, 255, 0, 4, 8, 0, 0, 0},
			NewPixelFormat(16), true},
		{[]uint8{32, 32, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			PixelFormat{BPP: 32, Depth: 32, BigEndian: RFBTrue, TrueColor: RFBFalse},
			true},
		//
		// Invalid PixelFormats.
		//
	}

	for _, tt := range tests {
		var buf bytes.Buffer
		buf.Write(tt.b)

		var pf PixelFormat
		err := pf.Unmarshal(buf.Bytes())
		if err == nil && !tt.ok {
			t.Error("expected error")
		}
		if err != nil {
			if verr, ok := err.(*VNCError); !ok {
				t.Errorf("unexpected %v error: %v", reflect.TypeOf(err), verr)
			}
		}
		if !tt.ok {
			continue
		}
		if got, want := pf, tt.pf; !equalPixelFormat(got, want) {
			t.Errorf("invalid pixel-format; got = %v, want = %v", pf, tt.pf)
		}
	}
}

func TestPixelFormat_String(t *testing.T) {
	for _, tt := range []struct {
		desc string
		pf   PixelFormat
		str  string
	}{
		{"8bpp-8depth",
			PixelFormat{BPP: 8, Depth: 8, BigEndian: RFBTrue, TrueColor: RFBFalse},
			"{ bpp: 8 depth: 8 big-endian: RFBTrue true-color: RFBFalse red-max: 0 green-max: 0 blue-max: 0 red-shift: 0 green-shift: 0 blue-shift: 0 }"},
	} {
		if got, want := tt.pf.String(), tt.str; got != want {
			t.Errorf("%s: string() = %q, want = %q", tt.desc, got, want)
		}
	}
}

func equalPixelFormat(g, w PixelFormat) bool {
	got, err := g.Marshal()
	if err != nil {
		return false
	}
	want, err := w.Marshal()
	if err != nil {
		return false
	}
	return operators.EqualSlicesOfByte(got, want)
}
