package tlssni

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// --- ClientHello construction helpers -------------------------------------

type chOpts struct {
	sni              string   // "" = omit server_name extension entirely
	legacyVersion    [2]byte  // ClientHello.legacy_version (also used as record version)
	supportedVersion []byte   // if non-nil, adds a supported_versions extension (TLS 1.3 style)
	extraExtBytes    []byte   // raw extra extension bytes appended after server_name
	cipherSuites     []uint16 // at least one required
}

func defaultOpts() chOpts {
	return chOpts{
		legacyVersion: [2]byte{0x03, 0x03},
		cipherSuites:  []uint16{0x1301},
	}
}

// buildClientHelloRecord builds a single TLS record (header + handshake
// header + ClientHello body) as sent on the wire.
func buildClientHelloRecord(o chOpts) []byte {
	var body bytes.Buffer
	body.Write(o.legacyVersion[:])
	body.Write(make([]byte, 32)) // random
	body.WriteByte(0)            // session_id length = 0

	var cs bytes.Buffer
	for _, c := range o.cipherSuites {
		var b [2]byte
		binary.BigEndian.PutUint16(b[:], c)
		cs.Write(b[:])
	}
	writeU16(&body, uint16(cs.Len()))
	body.Write(cs.Bytes())

	body.WriteByte(1) // compression methods length
	body.WriteByte(0) // null compression

	var exts bytes.Buffer
	if o.sni != "" {
		exts.Write(buildSNIExtension(o.sni))
	}
	if o.supportedVersion != nil {
		exts.Write(buildSupportedVersionsExtension(o.supportedVersion))
	}
	exts.Write(o.extraExtBytes)

	writeU16(&body, uint16(exts.Len()))
	body.Write(exts.Bytes())

	var hs bytes.Buffer
	hs.WriteByte(0x01) // HandshakeType ClientHello
	writeU24(&hs, uint32(body.Len()))
	hs.Write(body.Bytes())

	var rec bytes.Buffer
	rec.WriteByte(0x16)           // ContentType handshake
	rec.Write([]byte{0x03, 0x01}) // record version (compat value)
	writeU16(&rec, uint16(hs.Len()))
	rec.Write(hs.Bytes())

	return rec.Bytes()
}

func buildSNIExtension(host string) []byte {
	var entry bytes.Buffer
	entry.WriteByte(0x00) // name_type: host_name
	writeU16(&entry, uint16(len(host)))
	entry.WriteString(host)

	var list bytes.Buffer
	writeU16(&list, uint16(entry.Len()))
	list.Write(entry.Bytes())

	var ext bytes.Buffer
	writeU16(&ext, 0x0000) // extension_type: server_name
	writeU16(&ext, uint16(list.Len()))
	ext.Write(list.Bytes())
	return ext.Bytes()
}

func buildSupportedVersionsExtension(versions []byte) []byte {
	var ext bytes.Buffer
	writeU16(&ext, 0x002b) // extension_type: supported_versions
	inner := append([]byte{byte(len(versions))}, versions...)
	writeU16(&ext, uint16(len(inner)))
	ext.Write(inner)
	return ext.Bytes()
}

func writeU16(b *bytes.Buffer, v uint16) {
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], v)
	b.Write(buf[:])
}

func writeU24(b *bytes.Buffer, v uint32) {
	b.WriteByte(byte(v >> 16))
	b.WriteByte(byte(v >> 8))
	b.WriteByte(byte(v))
}

// splitInto breaks b into n roughly-equal chunks, simulating TCP segmentation.
func splitInto(b []byte, n int) [][]byte {
	if n <= 1 || len(b) == 0 {
		return [][]byte{b}
	}
	var chunks [][]byte
	chunkSize := (len(b) + n - 1) / n
	for i := 0; i < len(b); i += chunkSize {
		end := i + chunkSize
		if end > len(b) {
			end = len(b)
		}
		chunks = append(chunks, b[i:end])
	}
	return chunks
}

// --- Tests -----------------------------------------------------------------

func TestClientHelloTLS12WithSNI(t *testing.T) {
	rec := buildClientHelloRecord(defaultOpts_TLS12("api.example.com"))
	p := NewParser()
	res := p.Write(rec)
	if res != ResultFound {
		t.Fatalf("expected ResultFound, got %v", res)
	}
	if got := p.SNI(); got != "api.example.com" {
		t.Fatalf("SNI = %q, want %q", got, "api.example.com")
	}
}

func defaultOpts_TLS12(sni string) chOpts {
	o := defaultOpts()
	o.sni = sni
	o.legacyVersion = [2]byte{0x03, 0x03}
	o.cipherSuites = []uint16{0xc02f, 0xc030}
	return o
}

func TestClientHelloTLS13WithSNI(t *testing.T) {
	o := defaultOpts()
	o.sni = "registry.example.com"
	o.legacyVersion = [2]byte{0x03, 0x03} // TLS1.3 ClientHello still claims 3,3 here
	o.supportedVersion = []byte{0x03, 0x04}
	o.cipherSuites = []uint16{0x1301, 0x1302, 0x1303}

	rec := buildClientHelloRecord(o)
	p := NewParser()
	res := p.Write(rec)
	if res != ResultFound {
		t.Fatalf("expected ResultFound, got %v", res)
	}
	if got := p.SNI(); got != "registry.example.com" {
		t.Fatalf("SNI = %q, want %q", got, "registry.example.com")
	}
}

func TestClientHelloNoSNI(t *testing.T) {
	o := defaultOpts()
	rec := buildClientHelloRecord(o) // o.sni == ""
	p := NewParser()
	res := p.Write(rec)
	if res != ResultFound {
		t.Fatalf("expected ResultFound (valid ClientHello, just no SNI), got %v", res)
	}
	if got := p.SNI(); got != "" {
		t.Fatalf("SNI = %q, want empty", got)
	}
}

func TestClientHelloFragmentedAcrossPackets(t *testing.T) {
	o := defaultOpts()
	o.sni = "storage.example.net"
	rec := buildClientHelloRecord(o)

	for _, n := range []int{2, 3, 5, len(rec)} {
		t.Run("", func(t *testing.T) {
			chunks := splitInto(rec, n)
			p := NewParser()
			var res Result
			for _, c := range chunks {
				res = p.Write(c)
			}
			if res != ResultFound {
				t.Fatalf("split into %d chunks: expected ResultFound, got %v", n, res)
			}
			if got := p.SNI(); got != o.sni {
				t.Fatalf("split into %d chunks: SNI = %q, want %q", n, got, o.sni)
			}
		})
	}
}

func TestClientHelloOneByteAtATime(t *testing.T) {
	o := defaultOpts()
	o.sni = "one-byte-at-a-time.example.com"
	rec := buildClientHelloRecord(o)

	p := NewParser()
	var res Result
	for i := range rec {
		res = p.Write(rec[i : i+1])
		if res == ResultFound {
			break
		}
	}
	if res != ResultFound {
		t.Fatalf("expected ResultFound, got %v", res)
	}
	if got := p.SNI(); got != o.sni {
		t.Fatalf("SNI = %q, want %q", got, o.sni)
	}
}

// TestOutOfOrderAndRetransmission simulates what the *reassembler* would
// hand the parser after reordering: since the parser only ever sees
// already-in-order bytes (that's the reassembler's job), out-of-order
// packets and retransmissions at the TCP layer must not change the bytes
// the parser sees. This test documents/pins that contract: feeding the
// same in-order stream, plus a duplicate re-delivery of an already-seen
// prefix, still yields the correct SNI once the reassembler-equivalent
// in-order+deduped bytes are written.
func TestOutOfOrderAndRetransmissionAtParserLevel(t *testing.T) {
	o := defaultOpts()
	o.sni = "retransmit.example.com"
	rec := buildClientHelloRecord(o)
	mid := len(rec) / 2

	p := NewParser()
	// First segment arrives.
	if res := p.Write(rec[:mid]); res != ResultIncomplete {
		t.Fatalf("after first segment: expected ResultIncomplete, got %v", res)
	}
	// Simulate a retransmitted duplicate of a byte range being coalesced by
	// the reassembler into a no-op (nothing new to write) before the real
	// remainder shows up.
	if res := p.Write(nil); res != ResultIncomplete {
		t.Fatalf("after empty write: expected ResultIncomplete, got %v", res)
	}
	if res := p.Write(rec[mid:]); res != ResultFound {
		t.Fatalf("after remainder: expected ResultFound, got %v", res)
	}
	if got := p.SNI(); got != o.sni {
		t.Fatalf("SNI = %q, want %q", got, o.sni)
	}
}

func TestMultipleDistinctSNIsIndependentParsers(t *testing.T) {
	hosts := []string{
		"registry.example.com",
		"storage.example.net",
		"api.example.com",
	}
	for _, h := range hosts {
		o := defaultOpts()
		o.sni = h
		rec := buildClientHelloRecord(o)
		p := NewParser()
		if res := p.Write(rec); res != ResultFound {
			t.Fatalf("%s: expected ResultFound, got %v", h, res)
		}
		if got := p.SNI(); got != h {
			t.Fatalf("%s: SNI = %q", h, got)
		}
	}
}

func TestConcurrentConnectionsIndependentState(t *testing.T) {
	// Two "connections" = two independent Parser instances, interleaved
	// writes, must not cross-contaminate each other's extracted SNI.
	o1 := defaultOpts()
	o1.sni = "connection-one.example.com"
	rec1 := buildClientHelloRecord(o1)

	o2 := defaultOpts()
	o2.sni = "connection-two.example.com"
	rec2 := buildClientHelloRecord(o2)

	p1, p2 := NewParser(), NewParser()
	c1 := splitInto(rec1, 3)
	c2 := splitInto(rec2, 4)

	i, j := 0, 0
	for i < len(c1) || j < len(c2) {
		if i < len(c1) {
			p1.Write(c1[i])
			i++
		}
		if j < len(c2) {
			p2.Write(c2[j])
			j++
		}
	}

	if p1.SNI() != o1.sni {
		t.Fatalf("connection 1: SNI = %q, want %q", p1.SNI(), o1.sni)
	}
	if p2.SNI() != o2.sni {
		t.Fatalf("connection 2: SNI = %q, want %q", p2.SNI(), o2.sni)
	}
}

func TestMalformedTLSPayload(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{"not TLS at all", []byte("GET / HTTP/1.1\r\n\r\n")},
		{"wrong content type", []byte{0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5}},
		{"bad record version", []byte{0x16, 0x09, 0x09, 0x00, 0x05, 1, 2, 3, 4, 5}},
		{"truncated after content type", []byte{0x16}},
		{"garbage handshake type", func() []byte {
			rec := buildClientHelloRecord(defaultOpts())
			// corrupt the handshake type byte (first byte after 5-byte record header)
			rec[5] = 0xFF
			return rec
		}()},
		{"claimed length longer than data", []byte{0x16, 0x03, 0x03, 0x7F, 0xFF, 1, 2, 3}},
		{"handshake length exceeds record", func() []byte {
			rec := buildClientHelloRecord(defaultOpts())
			rec[6] = 0xFF // corrupt handshake length's high byte
			return rec
		}()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := NewParser()
			res := p.Write(tc.data)
			if res == ResultFound {
				t.Fatalf("expected malformed input to NOT produce ResultFound, got SNI=%q", p.SNI())
			}
			// Must not panic (test itself would crash), and must reach a
			// terminal, non-hanging state eventually.
		})
	}
}

func TestBufferLimitGivesUpOnOversizedOrNonTLSStream(t *testing.T) {
	p := NewParserWithLimit(64)
	junk := bytes.Repeat([]byte{0x16, 0x03, 0x03}, 100) // never resolves to a valid record
	var res Result
	for i := 0; i < len(junk); i += 8 {
		end := i + 8
		if end > len(junk) {
			end = len(junk)
		}
		res = p.Write(junk[i:end])
		if res != ResultIncomplete {
			break
		}
	}
	if res == ResultIncomplete {
		t.Fatalf("expected parser to give up before exhausting input, got ResultIncomplete")
	}
}

func TestClientHelloWithoutSNILooksLikeECHIsIgnoredNotErrored(t *testing.T) {
	// ECH conceals the real SNI inside an encrypted_client_hello extension;
	// from this parser's point of view that's simply "ClientHello parsed
	// fine, no (plaintext) server_name extension" - same as TestClientHelloNoSNI,
	// and must be reported as ResultFound with empty SNI, not as an error.
	o := defaultOpts()
	o.extraExtBytes = buildOpaqueExtension(0xfe0d, []byte{0, 1, 2, 3}) // encrypted_client_hello ext type, opaque payload
	rec := buildClientHelloRecord(o)

	p := NewParser()
	res := p.Write(rec)
	if res != ResultFound {
		t.Fatalf("expected ResultFound, got %v", res)
	}
	if got := p.SNI(); got != "" {
		t.Fatalf("SNI = %q, want empty (ECH conceals it)", got)
	}
}

func buildOpaqueExtension(extType uint16, data []byte) []byte {
	var ext bytes.Buffer
	writeU16(&ext, extType)
	writeU16(&ext, uint16(len(data)))
	ext.Write(data)
	return ext.Bytes()
}

// Real-world forward proxies (Squid and friends) expect an HTTP CONNECT
// tunnel request before the client starts TLS: the client sends the
// CONNECT request in the clear, then - on the very same TCP connection -
// starts the actual TLS ClientHello once the proxy replies "200 Connection
// established". Since the capture only sees the client->proxy direction,
// the CONNECT request and the ClientHello appear back-to-back in this
// stream's byte sequence, with nothing in between.

func TestClientHelloAfterHTTPConnectPreambleWholeAtOnce(t *testing.T) {
	o := defaultOpts()
	o.sni = "registry.example.com"
	preamble := "CONNECT registry.example.com:443 HTTP/1.1\r\nHost: registry.example.com:443\r\nUser-Agent: test/1.0\r\n\r\n"
	rec := buildClientHelloRecord(o)

	p := NewParser()
	res := p.Write(append([]byte(preamble), rec...))
	if res != ResultFound {
		t.Fatalf("expected ResultFound, got %v", res)
	}
	if got := p.SNI(); got != o.sni {
		t.Fatalf("SNI = %q, want %q", got, o.sni)
	}
}

func TestClientHelloAfterHTTPConnectPreambleSplitAtBoundary(t *testing.T) {
	o := defaultOpts()
	o.sni = "registry.example.com"
	preamble := "CONNECT registry.example.com:443 HTTP/1.1\r\nHost: registry.example.com:443\r\n\r\n"
	rec := buildClientHelloRecord(o)

	p := NewParser()
	if res := p.Write([]byte(preamble)); res != ResultIncomplete {
		t.Fatalf("after preamble only: expected ResultIncomplete, got %v", res)
	}
	res := p.Write(rec)
	if res != ResultFound {
		t.Fatalf("expected ResultFound, got %v", res)
	}
	if got := p.SNI(); got != o.sni {
		t.Fatalf("SNI = %q, want %q", got, o.sni)
	}
}

func TestClientHelloAfterHTTPConnectPreambleFragmented(t *testing.T) {
	// Mirrors a real capture: CONNECT line arrives in one TCP segment, the
	// ClientHello arrives split across several more.
	o := defaultOpts()
	o.sni = "ioc-gw-prod-eu-1c.example.net"
	preamble := "CONNECT ioc-gw-prod-eu-1c.example.net:443 HTTP/1.1\r\nHost: ioc-gw-prod-eu-1c.example.net:443\r\nUser-Agent: S1-LIN/25.2.2.14\r\n\r\n"
	rec := buildClientHelloRecord(o)

	full := append([]byte(preamble), rec...)
	p := NewParser()
	var res Result
	for _, chunk := range splitInto(full, 7) {
		res = p.Write(chunk)
		if res == ResultFound {
			break
		}
	}
	if res != ResultFound {
		t.Fatalf("expected ResultFound, got %v", res)
	}
	if got := p.SNI(); got != o.sni {
		t.Fatalf("SNI = %q, want %q", got, o.sni)
	}
}

func TestPlainHTTPWithoutFollowingTLSIsNotFound(t *testing.T) {
	// A CONNECT (or any HTTP request) with nothing TLS-shaped after it must
	// not be mistaken for a ClientHello, and must not hang forever either.
	p := NewParser()
	res := p.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"))
	if res != ResultIncomplete {
		t.Fatalf("expected ResultIncomplete (still waiting for a possible ClientHello), got %v", res)
	}
	res = p.Write([]byte("GET /health HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	if res == ResultFound {
		t.Fatalf("expected non-TLS follow-up data to NOT produce ResultFound")
	}
}
