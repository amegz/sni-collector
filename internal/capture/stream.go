package capture

import (
	"net"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/reassembly"

	"github.com/amix/sni-collector/internal/tlssni"
)

// streamFactory creates one stream per TCP flow (per reassembly.StreamPool
// semantics). Since the caller only ever feeds us packets destined for the
// proxy (see handlePacket), each flow here represents exactly one
// container-to-proxy direction of one TCP connection.
type streamFactory struct {
	sink      SNISink
	maxBuffer int
}

func (f *streamFactory) New(netFlow, _ gopacket.Flow, tcp *layers.TCP, _ reassembly.AssemblerContext) reassembly.Stream {
	return &sniStream{
		srcIP:   net.IP(append([]byte(nil), netFlow.Src().Raw()...)),
		srcPort: uint16(tcp.SrcPort),
		parser:  tlssni.NewParserWithLimit(f.maxBuffer),
		sink:    f.sink,
	}
}

// sniStream buffers just enough of one TCP flow to recognize a TLS
// ClientHello and pull the SNI out of it. Once a decision is reached
// (SNI found, no SNI, not TLS, or buffer limit hit) it stops buffering and
// discards all further payload for the connection, per the "don't hold the
// full stream" requirement.
type sniStream struct {
	srcIP   net.IP
	srcPort uint16
	parser  *tlssni.Parser
	sink    SNISink
	done    bool
}

func (s *sniStream) Accept(_ *layers.TCP, _ gopacket.CaptureInfo, _ reassembly.TCPFlowDirection, _ reassembly.Sequence, start *bool, _ reassembly.AssemblerContext) bool {
	// We only ever see one direction (client -> proxy) because handlePacket
	// filters on destination proxy IP:port before packets ever reach the
	// assembler, so every packet on this flow belongs to it.
	//
	// Force the reassembler to treat the first packet we see as the stream
	// start even if it isn't a SYN: the collector may attach to an
	// already-established connection (started before the process was
	// launched, or after a restart), and we'd otherwise buffer that flow's
	// packets forever waiting for a SYN that already passed.
	*start = true
	return true
}

func (s *sniStream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	if s.done {
		return
	}
	length, _ := sg.Lengths()
	if length == 0 {
		return
	}
	data := sg.Fetch(length)

	switch s.parser.Write(data) {
	case tlssni.ResultFound:
		s.done = true
		if sni := s.parser.SNI(); sni != "" && s.sink != nil {
			s.sink.Report(ac.GetCaptureInfo().Timestamp, s.srcIP, s.srcPort, sni)
		}
	case tlssni.ResultNotTLS, tlssni.ResultTooLarge:
		s.done = true
	case tlssni.ResultIncomplete:
		// keep buffering on subsequent ReassembledSG calls
	}
}

func (s *sniStream) ReassemblyComplete(_ reassembly.AssemblerContext) bool {
	// Nothing to flush; always safe to drop this stream's state.
	return true
}
