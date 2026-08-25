// Command sni-collector passively watches TCP traffic destined for a known
// HTTP/HTTPS proxy, reassembles TLS ClientHello messages, and logs the SNI
// (server_name) each connection asked for. It never terminates, proxies, or
// modifies traffic; it only reads from a packet capture handle.
package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/gopacket/gopacket/pcap"

	"github.com/amix/sni-collector/internal/capture"
	"github.com/amix/sni-collector/internal/dedup"
)

const (
	defaultSnapLen = 262144 // large enough for a jumbo-frame ClientHello segment

	// pcapReadTimeout bounds how long a single call into libpcap blocks
	// waiting for a packet. It must be a small positive value rather than
	// pcap.BlockForever: with an indefinite timeout, the read loop only
	// notices a shutdown request between packets, so on a quiet interface
	// handle.Close() can hang until traffic happens to arrive. A short
	// timeout makes shutdown responsive without meaningfully affecting
	// capture behavior (packets are still delivered as soon as they arrive).
	pcapReadTimeout = time.Second
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "sni-collector: "+err.Error())
		os.Exit(1)
	}
}

type config struct {
	iface       string
	proxyIP     string
	proxyPort   uint
	output      string
	deduplicate bool
	dedupTTL    time.Duration
	includePort bool
	dropUser    string
	promisc     bool
	idleTimeout time.Duration
	maxBuffer   int
}

func run() error {
	cfg := config{}

	fs := flag.NewFlagSet("sni-collector", flag.ContinueOnError)
	fs.Usage = func() { usage(fs) }

	fs.StringVar(&cfg.iface, "interface", "any", "network interface to capture on (\"any\" for all interfaces)")
	fs.StringVar(&cfg.proxyIP, "proxy-ip", "", "destination IP of the proxy to watch (required)")
	fs.UintVar(&cfg.proxyPort, "proxy-port", 3128, "destination TCP port of the proxy to watch")
	fs.StringVar(&cfg.output, "output", "", "path to append SNI log lines to (default: stdout)")
	fs.BoolVar(&cfg.deduplicate, "deduplicate", false, "suppress repeated (source IP, SNI) log lines within --dedup-ttl")
	fs.DurationVar(&cfg.dedupTTL, "dedup-ttl", time.Hour, "how long a (source IP, SNI) pair is suppressed after being logged, when --deduplicate is set")
	fs.BoolVar(&cfg.includePort, "log-source-port", false, "include the client's source TCP port in log lines")
	fs.StringVar(&cfg.dropUser, "drop-user", "", "if running as root, drop privileges to this user after opening the capture handle (recommended alternative: grant the binary cap_net_raw,cap_net_admin via setcap and run as a normal user; see README)")
	fs.BoolVar(&cfg.promisc, "promisc", false, "enable promiscuous mode on the capture interface")
	fs.DurationVar(&cfg.idleTimeout, "idle-timeout", 60*time.Second, "drop per-connection state for flows idle longer than this")
	fs.IntVar(&cfg.maxBuffer, "max-buffer", 32*1024, "maximum bytes of a single TCP flow buffered while looking for a ClientHello")
	showVersion := fs.Bool("version", false, "print version and exit")

	if err := fs.Parse(os.Args[1:]); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}

	if *showVersion {
		fmt.Println("sni-collector " + version)
		return nil
	}

	if cfg.proxyIP == "" {
		fs.Usage()
		return fmt.Errorf("--proxy-ip is required")
	}
	proxyIP := net.ParseIP(cfg.proxyIP)
	if proxyIP == nil {
		return fmt.Errorf("invalid --proxy-ip %q", cfg.proxyIP)
	}
	if cfg.proxyPort == 0 || cfg.proxyPort > 65535 {
		return fmt.Errorf("invalid --proxy-port %d", cfg.proxyPort)
	}

	out, closeOut, err := openOutput(cfg.output)
	if err != nil {
		return err
	}
	defer closeOut()

	handle, err := pcap.OpenLive(cfg.iface, defaultSnapLen, cfg.promisc, pcapReadTimeout)
	if err != nil {
		return fmt.Errorf("opening capture on %q: %w (need CAP_NET_RAW/CAP_NET_ADMIN or root; see README)", cfg.iface, err)
	}
	defer handle.Close()

	bpf := fmt.Sprintf("tcp and dst host %s and dst port %d", proxyIP.String(), cfg.proxyPort)
	if err := handle.SetBPFFilter(bpf); err != nil {
		return fmt.Errorf("setting BPF filter %q: %w", bpf, err)
	}

	if err := maybeDropPrivileges(cfg.dropUser); err != nil {
		return err
	}

	var dedupCache *dedup.Cache
	if cfg.deduplicate {
		dedupCache = dedup.New(cfg.dedupTTL)
	}
	sink := &logSink{
		w:           out,
		dedup:       dedupCache,
		includePort: cfg.includePort,
	}

	stop := make(chan struct{})
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		close(stop)
		handle.Close() // unblocks the capture loop's read
	}()

	if dedupCache != nil {
		sweepStop := make(chan struct{})
		defer close(sweepStop)
		go func() {
			t := time.NewTicker(cfg.dedupTTL)
			defer t.Stop()
			for {
				select {
				case <-sweepStop:
					return
				case <-t.C:
					dedupCache.Sweep()
				}
			}
		}()
	}

	capture.Run(handle, handle.LinkType(), capture.Config{
		ProxyIP:     proxyIP,
		ProxyPort:   uint16(cfg.proxyPort),
		MaxBuffer:   cfg.maxBuffer,
		IdleTimeout: cfg.idleTimeout,
	}, sink, stop)

	return nil
}

func usage(fs *flag.FlagSet) {
	fmt.Fprintf(os.Stderr, `sni-collector: passive TLS SNI collector for proxy-bound traffic

Watches TCP traffic destined for a known HTTP/HTTPS proxy, reassembles TLS
ClientHello messages, and logs the SNI (server_name) each connection asked
for. Purely passive: it only reads packets, it never modifies, delays, or
originates any network traffic.

Usage:
  sni-collector --proxy-ip 198.51.100.10 --proxy-port 3128 [flags]

Flags:
`)
	fs.PrintDefaults()
}

func openOutput(path string) (io.Writer, func(), error) {
	if path == "" {
		return os.Stdout, func() {}, nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return nil, nil, fmt.Errorf("opening --output %q: %w", path, err)
	}
	return f, func() { _ = f.Close() }, nil
}

// maybeDropPrivileges switches to an unprivileged user after the capture
// handle (which needed CAP_NET_RAW/CAP_NET_ADMIN or root) has already been
// opened. It is a best-effort convenience for the common "run as root via
// systemd" deployment; the preferred approach is to never run as root at
// all by granting the binary capabilities via setcap (see README).
func maybeDropPrivileges(username string) error {
	if username == "" {
		return nil
	}
	if os.Geteuid() != 0 {
		return nil
	}
	u, err := user.Lookup(username)
	if err != nil {
		return fmt.Errorf("looking up --drop-user %q: %w", username, err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return fmt.Errorf("parsing uid for %q: %w", username, err)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return fmt.Errorf("parsing gid for %q: %w", username, err)
	}
	if err := syscall.Setgroups([]int{gid}); err != nil {
		return fmt.Errorf("dropping supplementary groups: %w", err)
	}
	if err := syscall.Setgid(gid); err != nil {
		return fmt.Errorf("dropping to gid %d: %w", gid, err)
	}
	if err := syscall.Setuid(uid); err != nil {
		return fmt.Errorf("dropping to uid %d: %w", uid, err)
	}
	return nil
}

// logSink formats extracted SNIs as log lines and applies deduplication.
// Content policy: only timestamp, source IP, source port (optional), and
// SNI are ever written — never TLS payload, HTTP data, or anything else
// from the connection.
type logSink struct {
	mu          sync.Mutex
	w           io.Writer
	dedup       *dedup.Cache
	includePort bool
}

func (s *logSink) Report(ts time.Time, srcIP net.IP, srcPort uint16, sni string) {
	if sni == "" {
		// No SNI (e.g. ECH, or a ClientHello that legitimately omits it):
		// nothing useful to log, and not an error condition.
		return
	}
	if s.dedup != nil && s.dedup.Seen(srcIP.String()+"|"+sni) {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.includePort {
		fmt.Fprintf(s.w, "%s %s:%d %s\n", ts.Format(time.RFC3339), srcIP.String(), srcPort, sni)
	} else {
		fmt.Fprintf(s.w, "%s %s %s\n", ts.Format(time.RFC3339), srcIP.String(), sni)
	}
}
