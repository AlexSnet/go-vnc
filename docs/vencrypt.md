RFB Protocol section 6.2.19 - VeNCrypt Security Type:

After the VeNCrypt security type (19) is chosen, the server then sends
the highest version of the VeNCrypt RFB extension it supports, as two
U8s (major version followed by minor version)

```
No. of bytes    Type    [Value]         Description
1               U8                      Highest VeNCrypt major version
1               U8                      Highest VeNCrypt minor version
```

Currently the only defined versions are 0.1 and 0.2.
NB ideally, servers should support all VeNCrypt versions up to and
including this version, with the exception of protocol versions that
have been declared obsolete.

The client then responds with two U8s (major followed by minor)
indicating the version to be used (anything up to and including that
given by the server), or 0.0 if for some reason it can't support the
protocol:

```
No. of bytes    Type    [Value]         Description
1               U8                      Chosen VeNCrypt major version
1               U8                      Chosen VeNCrypt minor version
```

In the case of 0.0 the connection is closed at this point.


RFB Protocol section 6.2.19.0 - VeNCrypt Security Sub-type negotiation:
The server then responds with either a single U8, 0 for indicating that
the server can support the version chosen by the client or non-zero
(typically 255) for failure.  If non-zero, the connection is closed at
this point:

```
No. of bytes    Type    [Value]         Description
1               U8                      Success/Failure
```

Depending on the VeNCrypt version chosen and acknowledged by the server,
communication continues at section 6.2.19.0.1 (VeNCrypt protocol 0.1) or
6.2.19.0.2 (VeNCrypt protocol 0.2)


RFB Protocol Section 6.2.19.0.1 - VeNCrypt protocol 0.1

VeNCrypt protocol 0.1 is now obsolete, servers that show numbers higher
than 0.1 need not support it.

The server sends a U8 listing the number of sub-types supported.  If
this is zero, the connection terminates, otherwise it is followed by the
sub-types it supports/permits as U8s:

```
No. of bytes    Type    [Value]         Description
1               U8	[n]             Number of supported sub-types
n               U8 array                Supported sub-types
```

The sub-types are as follows:
19: Plain
20: TLSNone
21: TLSVnc
22: TLSPlain
23: X509None
24: X509Vnc
25: X509Plain

The client chooses one of these by sending back a single U8, or 0 for it
being unable to choose one.  If 0 is sent, the connection is closed at
this point:

```
No. of bytes    Type    [Value]         Description
1               U8                      Chosen sub-type
```

If 0 is sent, then the connection here is closed.  Otherwise,
communication continues as defined at:

Plain: section 6.2.19.256
TLSNone: section 6.2.19.257
TLSVnc: section 6.2.19.258
TLSPlain: section 6.2.19.259
X509None: section 6.2.19.260
X509Vnc: section 6.2.19.261
X509Plain: section 6.2.19.262

Other - typically 0, but might (maliciously) be something else:
Connection is closed


RFB Protocol Section 6.2.19.0.2 - VeNCrypt protocol 0.2

The server sends a U8 listing the number of sub-types supported.  If
this is zero, the connection terminates, otherwise it is followed by the
sub-types it supports/permits as U32s:
No. of bytes    Type    [Value]         Description
1               U8	[n]             Number of supported sub-types
4*n             U32 array               Supported sub-types

The sub-types are as follows:
0: Failure
256: Plain
257: TLSNone
258: TLSVnc
259: TLSPlain
260: X509None
261: X509Vnc
262: X509Plain

Note on version 0.2 sub-types: Sub-types 1 to 255 are reserved for
standard RFB types, should it be deemed useful to have them chosen at
this point in the in the VeNCrypt protocol (choosing 19 at this point
will never be allowed since it causes looping).  Sub-types 256 to
2^31 - 1 (i.e. values with the most significant [sign] bit not set) are
reserved as "official" future VeNCrypt sub-types, and may be requested
from VeNCrypt in the same way that new RFB types may be requested from
RealVNC Ltd.  Sub-types 2^31 to 2^32 - 1 (i.e. values with the most
significant [sign] bit set) may be used as "unofficial" types, allowing
the protocol to be extended without reference to VeNCrypt.

The client chooses one of these by sending back a single U32, or 0 for
it being unable to choose one.  If 0 is sent, the connection is closed
at this point:

```
No. of bytes    Type    [Value]         Description
4               U32                     Chosen sub-type
```

If 0 is sent, then the connection here is closed.  Otherwise,
communication continues as defined at:

Plain: section 6.2.19.256
TLSNone: section 6.2.19.257
TLSVnc: section 6.2.19.258
TLSPlain: section 6.2.19.259
X509None: section 6.2.19.260
X509Vnc: section 6.2.19.261
X509Plain: section 6.2.19.262

"Unofficial" sub-types - Any further behaviour is implementation
defined, however it is advised that any unsupported "unofficial" types
will be treated as "Other" below.

Other - typically 0, but might (maliciously) be something else:
Connection is closed.


RFB Protocol Section 6.2.19.256 - Plain VeNCrypt sub-type

If the Plain, TLSPlain or X509Plain sub-types have been chosen, the
client sends the username and password for the connection as follows:

No. of bytes    Type    [Value]         Description
4               U32                     Username Length
4               U32                     Password Length
Username Length U8 array                Username
Password Length U8 array                Password

The server then verifies:
a) that the specified user is permitted to connect
b) that the specified username and password are valid

NB See section 6.2.19.259 or 6.2.19.262 for communication that occurs
prior to this if the TLSPlain or X509Plain sub-types have been chosen.

Communication continues with the SecurityResult message


RFB Protocol Section 6.2.19.257 - TLSNone VeNCrypt sub-type

If the TLSNone, TLSVnc or TLSPlain sub-types have been chosen, Anonymous
TLS authentication is initiated as described in the TLS protocol.

If the TLS authentication was not successful, the connection is closed.
  Otherwise, all further communication takes place over the encrypted
TLS channel.

If the TLSNone sub-type was chosen, authentication continues as for the
None type described in section 6.2.1.


RFB Protocol Section 6.2.19.258 - TLSVnc VeNCrypt sub-type

TLSNone authentication takes place, as described in section 6.2.19.257,
followed by VNC authentication as described in section 6.2.2


RFB Protocol Section 6.2.19.259 - TLSPlain VeNCrypt sub-type

TLSNone authentication takes place, as described in section 6.2.19.257,
followed by Plain authentication as described in section 6.2.19.256

RFB Protocol Section 6.2.19.260 - X509None VeNCrypt sub-type

If the X509None, X509Vnc or X509Plain sub-types have been chosen, X509
certification based TLS authentication is initiated as described in the
TLS protocol.

If the X509/TLS authentication was not successful, the connection is
closed.   Otherwise, all further communication takes place over the
encrypted TLS channel.

If the X509None sub-type was chosen, authentication continues as for the
None type described in section 6.2.1.


RFB Protocol Section 6.2.19.261 - X509Vnc VeNCrypt sub-type

X509None authentication takes place, as described in section 6.2.19.260,
followed by VNC authentication as described in section 6.2.2


RFB Protocol Section 6.2.19.262 - X509Plain VeNCrypt sub-type

X509None authentication takes place, as described in section 6.2.19.260,
followed by Plain authentication as described in section 6.2.19.256


## Library notes

This client implements VeNCrypt **0.2** only. If the server advertises 0.1 (or
any other unsupported version), the client sends 0.0 and closes.

Supported 0.2 sub-types, in preference order:

- 261 X509Vnc
- 258 TLSVnc
- 260 X509None
- 257 TLSNone

Plain (256) and the TLSPlain/X509Plain variants are not implemented.

After the client sends the chosen sub-type, this library expects a status
byte used by common implementations (including noVNC): `1` means the
sub-type was accepted, `0` means it was rejected. TLS then proceeds with
`InsecureSkipVerify` enabled; X.509 and anonymous TLS are treated the same
at the TLS layer.


