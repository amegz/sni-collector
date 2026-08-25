// Package capture wires packet capture (live or offline) to TCP stream
// reassembly and TLS SNI extraction. It never looks at traffic other than
// TCP segments addressed to the configured proxy IP:port, and it never
// buffers more than a bounded amount of payload per connection.
package capture

import (
	"net"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/reassembly"

	"github.com/amix/sni-collector/internal/tlssni"
)

// Config controls what traffic is inspected and how aggressively per-flow
// state is bounded and expired.
type Config struct {
	// ProxyIP/ProxyPort select which TCP traffic is inspected: only packets
	// whose destination matches both are handed to the reassembler.
	ProxyIP   net.IP
	ProxyPort uint16

	// MaxBuffer bounds how many bytes of a single TCP flow are buffered
	// while waiting for a complete ClientHello (see tlssni.DefaultMaxBuffer).
	MaxBuffer int

	// IdleTimeout is how long a flow may sit without new data before its
	// state is dropped by the periodic flush.
	IdleTimeout time.Duration

	// FlushInterval is how often the periodic flush runs.
	FlushInterval time.Duration
}

func (c *Config) withDefaults() Config {
	out := *c
	if out.MaxBuffer <= 0 {
		out.MaxBuffer = tlssni.DefaultMaxBuffer
	}
	if out.IdleTimeout <= 0 {
		out.IdleTimeout = 60 * time.Second
	}
	if out.FlushInterval <= 0 {
		out.FlushInterval = 10 * time.Second
	}
	return out
}

// SNISink receives extracted SNI values. Report is called once per
// connection that yields a non-empty SNI; callers handle logging and
// deduplication.
type SNISink interface {
	Report(ts time.Time, srcIP net.IP, srcPort uint16, sni string)
}

// Run reads packets from src (a live *pcap.Handle or an offline reader such
// as *pcapgo.Reader — anything implementing gopacket.PacketDataSource) until
// the source is exhausted or stop is closed, feeding matching TCP flows
// through reassembly and TLS ClientHello parsing.
//
// Run returns when the packet source is exhausted (offline reads) or stop
// fires (live capture shutdown). It never panics on malformed input.
func Run(src gopacket.PacketDataSource, linkType layers.LinkType, cfg Config, sink SNISink, stop <-chan struct{}) {
	cfg = cfg.withDefaults()

	factory := &streamFactory{sink: sink, maxBuffer: cfg.MaxBuffer}
	pool := reassembly.NewStreamPool(factory)
	assembler := reassembly.NewAssembler(pool)

	packetSource := gopacket.NewPacketSource(src, linkType)
	packetSource.NoCopy = true

	ticker := time.NewTicker(cfg.FlushInterval)
	defer ticker.Stop()

	packets := packetSource.Packets()
	for {
		select {
		case <-stop:
			assembler.FlushAll()
			return
		case <-ticker.C:
			assembler.FlushCloseOlderThan(time.Now().Add(-cfg.IdleTimeout))
		case pkt, ok := <-packets:
			if !ok {
				assembler.FlushAll()
				return
			}
			handlePacket(pkt, &cfg, assembler)
		}
	}
}

// handlePacket filters to TCP segments destined for the proxy and feeds them
// into the reassembler. It recovers from any panic triggered by malformed
// packet bytes so a single bad packet can never take down the collector.
func handlePacket(pkt gopacket.Packet, cfg *Config, assembler *reassembly.Assembler) {
	defer func() { _ = recover() }()

	dst, ok := packetDstIP(pkt)
	if !ok || !dst.Equal(cfg.ProxyIP) {
		return
	}
	tcpLayer := pkt.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}
	tcp, ok := tcpLayer.(*layers.TCP)
	if !ok {
		return
	}
	if uint16(tcp.DstPort) != cfg.ProxyPort {
		return
	}
	netLayer := pkt.NetworkLayer()
	if netLayer == nil {
		return
	}
	meta := pkt.Metadata()
	if meta == nil {
		return
	}
	assembler.AssembleWithContext(netLayer.NetworkFlow(), tcp, &captureContext{ci: meta.CaptureInfo})
}

func packetDstIP(pkt gopacket.Packet) (net.IP, bool) {
	if ip4 := pkt.Layer(layers.LayerTypeIPv4); ip4 != nil {
		return ip4.(*layers.IPv4).DstIP, true
	}
	if ip6 := pkt.Layer(layers.LayerTypeIPv6); ip6 != nil {
		return ip6.(*layers.IPv6).DstIP, true
	}
	return nil, false
}

type captureContext struct {
	ci gopacket.CaptureInfo
}

func (c *captureContext) GetCaptureInfo() gopacket.CaptureInfo { return c.ci }
