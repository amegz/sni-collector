// Package tlssni implements a minimal, allocation-conscious parser that looks
// for a TLS ClientHello handshake message inside a byte stream and extracts
// the SNI (server_name) extension, if present.
//
// The parser never decrypts anything: it only walks the plaintext TLS record
// and handshake framing that precedes encryption (ClientHello is always
// sent in the clear, in both TLS 1.2 and TLS 1.3). It deliberately does not
// look past the ClientHello.
package tlssni

import (
	"encoding/binary"
	"errors"
)

// Result is the outcome of feeding bytes to a Parser.
type Result int

const (
	// ResultIncomplete means more bytes are needed before a decision can be made.
	ResultIncomplete Result = iota
	// ResultFound means a ClientHello was fully parsed and SNI (if any) was extracted.
	// Check Parser.SNI() for the value; it may be empty if the ClientHello carried
	// no server_name extension (e.g. ECH, or a raw IP connection).
	ResultFound
	// ResultNotTLS means the stream does not look like a TLS handshake at all
	// (bad record type/version) and should be abandoned.
	ResultNotTLS
	// ResultTooLarge means the ClientHello (or the buffering needed to reach it)
	// exceeded the configured limit and the caller should give up.
	ResultTooLarge
)

const (
	recordHeaderLen  = 5
	handshakeHdrLen  = 4
	contentHandshake = 0x16
	handshakeClient  = 0x01
	extServerName    = 0x00
	sniHostName      = 0x00

	// DefaultMaxBuffer bounds how many bytes of a single TCP stream we are
	// willing to buffer while waiting for a complete ClientHello. This keeps
	// memory bounded per-connection and lets us give up quickly on streams
	// that are not a ClientHello (or are pathologically large).
	DefaultMaxBuffer = 32 * 1024
)

var errMalformed = errors.New("tlssni: malformed TLS ClientHello")

// Parser incrementally accumulates bytes from one TCP flow direction and
// tries to recognize a single TLS record containing a ClientHello.
//
// It is not safe for concurrent use.
type Parser struct {
	buf       []byte
	maxBuffer int
	sni       string
	done      bool
}

// NewParser creates a Parser with the default buffer cap.
func NewParser() *Parser {
	return &Parser{maxBuffer: DefaultMaxBuffer}
}

// NewParserWithLimit creates a Parser with a custom buffer cap (bytes).
func NewParserWithLimit(maxBuffer int) *Parser {
	if maxBuffer <= 0 {
		maxBuffer = DefaultMaxBuffer
	}
	return &Parser{maxBuffer: maxBuffer}
}

// SNI returns the extracted server name after Write returned ResultFound.
// It is empty if the ClientHello had no server_name extension.
func (p *Parser) SNI() string { return p.sni }

// Write feeds newly-reassembled, in-order bytes belonging to the flow into
// the parser. It never panics on malformed input; malformed or unrecognized
// data yields ResultNotTLS / ResultTooLarge rather than an error, since the
// caller (packet capture) must never crash on untrusted network input.
func (p *Parser) Write(b []byte) Result {
	if p.done {
		return ResultFound
	}
	if len(b) > 0 {
		if len(p.buf)+len(b) > p.maxBuffer {
			// Avoid unbounded growth on non-TLS or oversized handshakes.
			room := p.maxBuffer - len(p.buf)
			if room > 0 {
				p.buf = append(p.buf, b[:room]...)
			}
		} else {
			p.buf = append(p.buf, b...)
		}
	}

	sni, res := tryParse(p.buf)
	switch res {
	case ResultFound:
		p.sni = sni
		p.done = true
		return ResultFound
	case ResultNotTLS:
		p.done = true
		return ResultNotTLS
	case ResultIncomplete:
		if len(p.buf) >= p.maxBuffer {
			p.done = true
			return ResultTooLarge
		}
		return ResultIncomplete
	default:
		return res
	}
}

// tryParse attempts to parse a complete TLS record + ClientHello out of buf.
// It returns ResultIncomplete if buf might become parseable with more data,
// ResultNotTLS if the leading bytes are clearly not a TLS handshake record,
// and ResultFound with the extracted SNI (possibly empty) otherwise.
func tryParse(buf []byte) (string, Result) {
	if len(buf) < 1 {
		return "", ResultIncomplete
	}
	if buf[0] != contentHandshake {
		// Not a TLS handshake record (could be a different content type,
		// or not TLS at all, e.g. plain HTTP CONNECT to the proxy).
		return "", ResultNotTLS
	}
	if len(buf) < 3 {
		return "", ResultIncomplete
	}
	// buf[1:3] is the "legacy record version". Any 0x03,0x0{1..4} is
	// plausible (SSLv3 through TLS 1.3, which still says 0x0301/0x0303
	// here for compatibility). Reject anything else outright.
	if buf[1] != 0x03 {
		return "", ResultNotTLS
	}

	if len(buf) < recordHeaderLen {
		return "", ResultIncomplete
	}
	recLen := int(binary.BigEndian.Uint16(buf[3:5]))
	if recLen == 0 || recLen > 0x4000+256 { // generous cap above the 16KB record max
		return "", ResultNotTLS
	}
	total := recordHeaderLen + recLen
	if len(buf) < total {
		return "", ResultIncomplete
	}

	// NOTE: a ClientHello can in theory span multiple TLS records, but in
	// practice every TLS stack emits it as a single record; we only handle
	// the single-record case, matching the spec's "no full DPI" scope.
	rec := buf[recordHeaderLen:total]
	sni, err := parseClientHello(rec)
	if err != nil {
		return "", ResultNotTLS
	}
	return sni, ResultFound
}

// parseClientHello parses the handshake-layer framing and, inside it, the
// ClientHello body, returning the SNI host name (or "" if none present).
func parseClientHello(rec []byte) (string, error) {
	if len(rec) < handshakeHdrLen {
		return "", errMalformed
	}
	if rec[0] != handshakeClient {
		return "", errMalformed
	}
	hsLen := int(rec[1])<<16 | int(rec[2])<<8 | int(rec[3])
	body := rec[handshakeHdrLen:]
	if hsLen > len(body) {
		// Handshake body doesn't fit in the record we have; we intentionally
		// don't support ClientHellos split across multiple TLS records.
		return "", errMalformed
	}
	body = body[:hsLen]
	return parseClientHelloBody(body)
}

func parseClientHelloBody(b []byte) (string, error) {
	r := &cursor{b: b}

	// client_version (2 bytes)
	if !r.skip(2) {
		return "", errMalformed
	}
	// random (32 bytes)
	if !r.skip(32) {
		return "", errMalformed
	}
	// session_id: 1-byte length prefix
	sidLen, ok := r.readU8()
	if !ok || !r.skip(int(sidLen)) {
		return "", errMalformed
	}
	// cipher_suites: 2-byte length prefix (bytes)
	csLen, ok := r.readU16()
	if !ok || !r.skip(int(csLen)) {
		return "", errMalformed
	}
	// compression_methods: 1-byte length prefix
	cmLen, ok := r.readU8()
	if !ok || !r.skip(int(cmLen)) {
		return "", errMalformed
	}
	if r.remaining() == 0 {
		// No extensions block at all -> no SNI, but a structurally valid
		// (if unusual, e.g. SSLv3-style) ClientHello.
		return "", nil
	}
	// extensions: 2-byte total length prefix
	extTotalLen, ok := r.readU16()
	if !ok {
		return "", errMalformed
	}
	extBytes, ok := r.readN(int(extTotalLen))
	if !ok {
		return "", errMalformed
	}

	return findSNI(extBytes)
}

func findSNI(ext []byte) (string, error) {
	r := &cursor{b: ext}
	for r.remaining() > 0 {
		extType, ok := r.readU16()
		if !ok {
			return "", errMalformed
		}
		extLen, ok := r.readU16()
		if !ok {
			return "", errMalformed
		}
		extData, ok := r.readN(int(extLen))
		if !ok {
			return "", errMalformed
		}
		if extType != extServerName {
			continue
		}
		return parseServerNameExtension(extData)
	}
	return "", nil
}

// parseServerNameExtension parses the contents of the server_name (SNI)
// extension and returns the first host_name entry, if any.
func parseServerNameExtension(data []byte) (string, error) {
	r := &cursor{b: data}
	listLen, ok := r.readU16()
	if !ok {
		return "", errMalformed
	}
	list, ok := r.readN(int(listLen))
	if !ok {
		return "", errMalformed
	}
	lr := &cursor{b: list}
	for lr.remaining() > 0 {
		nameType, ok := lr.readU8()
		if !ok {
			return "", errMalformed
		}
		nameLen, ok := lr.readU16()
		if !ok {
			return "", errMalformed
		}
		name, ok := lr.readN(int(nameLen))
		if !ok {
			return "", errMalformed
		}
		if nameType == sniHostName {
			return string(name), nil
		}
		// Unknown name type: skip and keep looking.
	}
	return "", nil
}

// cursor is a tiny bounds-checked byte reader used to keep the parsing
// functions above free of manual index arithmetic (and the off-by-one bugs
// that come with it) when handling attacker-controlled/malformed input.
type cursor struct {
	b   []byte
	off int
}

func (c *cursor) remaining() int { return len(c.b) - c.off }

func (c *cursor) skip(n int) bool {
	if n < 0 || c.remaining() < n {
		return false
	}
	c.off += n
	return true
}

func (c *cursor) readU8() (byte, bool) {
	if c.remaining() < 1 {
		return 0, false
	}
	v := c.b[c.off]
	c.off++
	return v, true
}

func (c *cursor) readU16() (uint16, bool) {
	if c.remaining() < 2 {
		return 0, false
	}
	v := binary.BigEndian.Uint16(c.b[c.off : c.off+2])
	c.off += 2
	return v, true
}

func (c *cursor) readN(n int) ([]byte, bool) {
	if n < 0 || c.remaining() < n {
		return nil, false
	}
	v := c.b[c.off : c.off+n]
	c.off += n
	return v, true
}
