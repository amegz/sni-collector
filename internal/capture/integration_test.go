package capture_test

// Integration test: builds a real .pcap file byte-for-byte (Ethernet + IPv4
// + TCP framing, written with pcapgo so no libpcap/cgo is needed to run
// `go test`), replicating a typical deployment scenario:
//
//	192.0.2.10 -> 198.51.100.10:3128   SNI: registry.example.com
//	192.0.2.10 -> 198.51.100.10:3128   SNI: storage.example.net
//
// One connection's ClientHello is delivered out of order with a retransmit;
// the other is interleaved with it packet-by-packet to exercise concurrent
// connections.

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/amix/sni-collector/internal/capture"
)

const (
	proxyIP    = "198.51.100.10"
	proxyPort  = 3128
	clientIP   = "192.0.2.10"
	clientMAC0 = "\x02\x00\x00\x00\x00\x01"
	proxyMAC0  = "\x02\x00\x00\x00\x00\x02"
)

// buildClientHelloRecord returns the raw bytes of a minimal, valid single
// TLS record containing a ClientHello with the given SNI.
func buildClientHelloRecord(sni string) []byte {
	var body bytes.Buffer
	body.Write([]byte{0x03, 0x03}) // legacy_version
	body.Write(make([]byte, 32))   // random
	body.WriteByte(0)              // session_id len
	putU16(&body, 2)               // cipher_suites len
	body.Write([]byte{0x13, 0x01}) // TLS_AES_128_GCM_SHA256
	body.WriteByte(1)              // compression_methods len
	body.WriteByte(0)              // null compression

	var sniEntry bytes.Buffer
	sniEntry.WriteByte(0) // host_name
	putU16(&sniEntry, uint16(len(sni)))
	sniEntry.WriteString(sni)

	var sniList bytes.Buffer
	putU16(&sniList, uint16(sniEntry.Len()))
	sniList.Write(sniEntry.Bytes())

	var ext bytes.Buffer
	putU16(&ext, 0x0000) // server_name
	putU16(&ext, uint16(sniList.Len()))
	ext.Write(sniList.Bytes())

	putU16(&body, uint16(ext.Len()))
	body.Write(ext.Bytes())

	var hs bytes.Buffer
	hs.WriteByte(0x01) // ClientHello
	hs.WriteByte(byte(body.Len() >> 16))
	hs.WriteByte(byte(body.Len() >> 8))
	hs.WriteByte(byte(body.Len()))
	hs.Write(body.Bytes())

	var rec bytes.Buffer
	rec.WriteByte(0x16)
	rec.Write([]byte{0x03, 0x01})
	putU16(&rec, uint16(hs.Len()))
	rec.Write(hs.Bytes())
	return rec.Bytes()
}

func putU16(b *bytes.Buffer, v uint16) {
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], v)
	b.Write(buf[:])
}

// pcapBuilder accumulates (timestamp-ordered) packets destined for a pcap file.
type pcapBuilder struct {
	t       *testing.T
	ts      time.Time
	packets []struct {
		ci   gopacket.CaptureInfo
		data []byte
	}
}

func newPcapBuilder(t *testing.T) *pcapBuilder {
	return &pcapBuilder{t: t, ts: time.Date(2026, 8, 25, 12, 39, 29, 0, time.UTC)}
}

// segment appends one client->proxy TCP segment (optionally with SYN set and
// with the given payload) to the capture, in the order this method is
// called -- which is what determines "arrival order" for the reassembler.
func (b *pcapBuilder) segment(srcPort uint16, seq uint32, syn bool, payload []byte) {
	b.t.Helper()

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr(clientMAC0),
		DstMAC:       net.HardwareAddr(proxyMAC0),
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.ParseIP(clientIP).To4(),
		DstIP:    net.ParseIP(proxyIP).To4(),
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(proxyPort),
		Seq:     seq,
		Window:  65535,
		SYN:     syn,
		ACK:     !syn,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		b.t.Fatalf("SetNetworkLayerForChecksum: %v", err)
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	var payloadLayer gopacket.SerializableLayer
	if len(payload) > 0 {
		payloadLayer = gopacket.Payload(payload)
		if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, payloadLayer); err != nil {
			b.t.Fatalf("serialize: %v", err)
		}
	} else {
		if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp); err != nil {
			b.t.Fatalf("serialize: %v", err)
		}
	}

	data := append([]byte(nil), buf.Bytes()...)
	b.ts = b.ts.Add(time.Millisecond)
	b.packets = append(b.packets, struct {
		ci   gopacket.CaptureInfo
		data []byte
	}{
		ci: gopacket.CaptureInfo{
			Timestamp:     b.ts,
			CaptureLength: len(data),
			Length:        len(data),
		},
		data: data,
	})
}

// unrelatedSegment adds a packet that must be ignored (wrong destination
// port), to prove the collector doesn't just process everything in the
// pcap file.
func (b *pcapBuilder) unrelatedSegment() {
	b.t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr(clientMAC0),
		DstMAC:       net.HardwareAddr(proxyMAC0),
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP,
		SrcIP: net.ParseIP(clientIP).To4(), DstIP: net.ParseIP(proxyIP).To4(),
	}
	tcp := &layers.TCP{SrcPort: 55555, DstPort: 443, Seq: 1, ACK: true, Window: 65535}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		b.t.Fatalf("SetNetworkLayerForChecksum: %v", err)
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	payload := gopacket.Payload([]byte("not tls, wrong port, must be ignored"))
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, payload); err != nil {
		b.t.Fatalf("serialize: %v", err)
	}
	data := append([]byte(nil), buf.Bytes()...)
	b.ts = b.ts.Add(time.Millisecond)
	b.packets = append(b.packets, struct {
		ci   gopacket.CaptureInfo
		data []byte
	}{ci: gopacket.CaptureInfo{Timestamp: b.ts, CaptureLength: len(data), Length: len(data)}, data: data})
}

func (b *pcapBuilder) writeTo(path string) {
	b.t.Helper()
	f, err := os.Create(path)
	if err != nil {
		b.t.Fatalf("create pcap: %v", err)
	}
	defer f.Close()

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		b.t.Fatalf("write pcap header: %v", err)
	}
	for _, p := range b.packets {
		if err := w.WritePacket(p.ci, p.data); err != nil {
			b.t.Fatalf("write packet: %v", err)
		}
	}
}

type recordedSNI struct {
	srcIP   string
	srcPort uint16
	sni     string
}

type collectingSink struct {
	mu   sync.Mutex
	seen []recordedSNI
}

func (s *collectingSink) Report(_ time.Time, srcIP net.IP, srcPort uint16, sni string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen = append(s.seen, recordedSNI{srcIP: srcIP.String(), srcPort: srcPort, sni: sni})
}

func TestIntegrationRealPcapTwoConnectionsWithReorderAndRetransmit(t *testing.T) {
	const (
		portA = 54321 // out-of-order + retransmit
		portB = 54322 // straightforward, interleaved with A
	)

	recA := buildClientHelloRecord("registry.example.com")
	recB := buildClientHelloRecord("storage.example.net")

	// Split A's ClientHello into three segments.
	a0, a1, a2 := recA[:10], recA[10:40], recA[40:]
	// Split B's ClientHello into two segments.
	b0, b1 := recB[:20], recB[20:]

	const isnA, isnB uint32 = 1000, 5000

	pb := newPcapBuilder(t)

	// Connection B's SYN, then connection A's SYN (interleaved setup).
	pb.segment(portB, isnB, true, nil)
	pb.segment(portA, isnA, true, nil)

	// Connection A: send segment 0, then (out of order) segment 2, then a
	// retransmit of segment 0, then finally segment 1 to fill the gap.
	seqA0 := isnA + 1
	seqA1 := seqA0 + uint32(len(a0))
	seqA2 := seqA1 + uint32(len(a1))
	pb.segment(portA, seqA0, false, a0)
	pb.segment(portA, seqA2, false, a2) // out of order
	pb.segment(portA, seqA0, false, a0) // retransmission (duplicate)

	// Connection B's first segment, interleaved between A's reordered packets.
	seqB0 := isnB + 1
	seqB1 := seqB0 + uint32(len(b0))
	pb.segment(portB, seqB0, false, b0)

	// Now fill connection A's gap; ClientHello should complete here.
	pb.segment(portA, seqA1, false, a1)

	// Finish connection B.
	pb.segment(portB, seqB1, false, b1)

	// Noise that must be filtered out (wrong destination port).
	pb.unrelatedSegment()

	pcapPath := filepath.Join(t.TempDir(), "integration_sample.pcap")
	pb.writeTo(pcapPath)

	f, err := os.Open(pcapPath)
	if err != nil {
		t.Fatalf("open pcap: %v", err)
	}
	defer f.Close()

	reader, err := pcapgo.NewReader(f)
	if err != nil {
		t.Fatalf("pcapgo.NewReader: %v", err)
	}

	sink := &collectingSink{}
	stop := make(chan struct{})
	capture.Run(reader, reader.LinkType(), capture.Config{
		ProxyIP:   net.ParseIP(proxyIP),
		ProxyPort: proxyPort,
	}, sink, stop)

	sink.mu.Lock()
	defer sink.mu.Unlock()

	if len(sink.seen) != 2 {
		t.Fatalf("got %d reported SNIs, want 2: %+v", len(sink.seen), sink.seen)
	}

	got := map[string]recordedSNI{}
	for _, r := range sink.seen {
		got[r.sni] = r
	}

	wantA, ok := got["registry.example.com"]
	if !ok {
		t.Fatalf("missing SNI for connection A; got %+v", sink.seen)
	}
	if wantA.srcIP != clientIP || wantA.srcPort != portA {
		t.Errorf("connection A: srcIP=%s srcPort=%d, want %s:%d", wantA.srcIP, wantA.srcPort, clientIP, portA)
	}

	wantB, ok := got["storage.example.net"]
	if !ok {
		t.Fatalf("missing SNI for connection B; got %+v", sink.seen)
	}
	if wantB.srcIP != clientIP || wantB.srcPort != portB {
		t.Errorf("connection B: srcIP=%s srcPort=%d, want %s:%d", wantB.srcIP, wantB.srcPort, clientIP, portB)
	}
}
