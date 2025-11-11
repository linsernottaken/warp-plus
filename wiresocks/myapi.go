package wiresocks

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bepass-org/warp-plus/myipscanner"
	"github.com/bepass-org/warp-plus/proxy/pkg/mixed"
	"github.com/bepass-org/warp-plus/proxy/pkg/statute"
	"github.com/bepass-org/warp-plus/warp"
	"github.com/bepass-org/warp-plus/wireguard/tun/netstack"
	"github.com/sagernet/sing/common/buf"
)

func init() {
	debug.SetGCPercent(30)
	debug.SetMemoryLimit(35 * 1024 * 1024)
}

type APIScanOptions struct {
	Endpoints    string
	ScannerPorts string
	V4           bool
	V6           bool
	MaxRTT       time.Duration
	ScanTimeout  time.Duration
	PrivateKey   string
	PublicKey    string
}

func APIRunScan(ctx context.Context, l *slog.Logger, opts APIScanOptions) (result []myipscanner.IPInfo, err error) {
	scanCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Stop the scan as soon as the first good IP is found.
	const desiredIPs = 1

	// Initialize scanner options
	scannerOptions := []myipscanner.Option{
		myipscanner.WithLogger(l.With(slog.String("subsystem", "scanner"))),
		myipscanner.WithWarpPrivateKey(opts.PrivateKey),
		myipscanner.WithWarpPeerPublicKey(opts.PublicKey),
		myipscanner.WithUseIPv4(opts.V4),
		myipscanner.WithUseIPv6(opts.V6),
		myipscanner.WithMaxDesirableRTT(opts.MaxRTT * time.Second),
		myipscanner.WithConcurrentScanners(10),
		myipscanner.WithStopOnFirstGoodIPs(desiredIPs),
		myipscanner.WithBucketSize(1),
		myipscanner.WithTCPPingFilterRTT(300 * time.Millisecond),
		myipscanner.WithScanTimeout(opts.ScanTimeout),
	}

	// Supports:
	// 1. a single or multiple ip:port separated by "," (e.g., 192.168.1.1:8080, [2001:db8::1]:2408)
	// 2. one or multiple ip ranges (CIDR) separated by "," (e.g., 192.168.1.0/24, 2606:4700:d0::/48)
	// 3. a single or multiple ip separated by "," (e.g., 192.168.1.1, 2001:db8::1)
	// 4. a single domain with port (e.g., example.com:8443)
	// 5. a single domain without port (e.g., example.com)

	// If user does not specify custom endpoints, use the default WARP IP ranges for scanning.
	// This ensures that both IPv4 and IPv6 ranges are scanned if enabled.
	if opts.Endpoints == "" {
		l.Debug("no endpoints provided, using default WARP prefixes for scanning")
		scannerOptions = append(scannerOptions, myipscanner.WithCidrList(warp.APIWarpPrefixes()))
	} else {
		parts := strings.Split(opts.Endpoints, ",")
		for _, part := range parts {
			trimmedPart := strings.TrimSpace(part)
			if trimmedPart == "" {
				continue // Skip empty parts
			}

			// Case 1: Is it a valid CIDR? (e.g., 192.168.1.0/24)
			if prefix, err := netip.ParsePrefix(trimmedPart); err == nil {
				scannerOptions = append(scannerOptions, myipscanner.WithAppendCidrList(prefix))
				continue
			}

			// Case 2 & 3: Is it a valid ip:port or domain:port? (e.g., 1.1.1.1:8080 or example.com:8443)
			_, portStr, err := net.SplitHostPort(trimmedPart)
			if err == nil {
				// Validate the port number.
				port, err := strconv.Atoi(portStr)
				if err != nil || port < 0 || port > 65535 {
					return nil, errors.New("invalid port number: " + portStr)
				}
				scannerOptions = append(scannerOptions, myipscanner.WithAppendCustomEndpoint(trimmedPart))
				continue
			}

			// Case 4: Is it a single IP address without a port? (e.g., 192.168.1.1)
			// Use ":0" to signal random WARP port selection.
			if _, err := netip.ParseAddr(trimmedPart); err == nil {
				endpointWithPort := net.JoinHostPort(trimmedPart, "0")
				scannerOptions = append(scannerOptions, myipscanner.WithAppendCustomEndpoint(endpointWithPort))
				continue
			}

			// Case 5: Is it a domain without a port? (e.g., example.com)
			if strings.Contains(trimmedPart, ".") && !strings.ContainsAny(trimmedPart, "/:") {
				endpointWithPort := net.JoinHostPort(trimmedPart, "0")
				scannerOptions = append(scannerOptions, myipscanner.WithAppendCustomEndpoint(endpointWithPort))
				continue
			}

			// Format is invalid
			return nil, errors.New("invalid endpoint format: " + trimmedPart)
		}
	}

	// Set default scan ports
	if opts.ScannerPorts != "" {
		scannerOptions = append(scannerOptions, myipscanner.WithCustomScanPorts(opts.ScannerPorts))
	}

	scanner := myipscanner.NewScanner(scannerOptions...)

	// Blocks
	scanner.Run(scanCtx)

	// After the run, get the results.
	ipList := scanner.GetAvailableIPs()

	// Check if we found any IPs.
	if len(ipList) == 0 {
		// If the context was canceled, that's the primary error.
		if scanCtx.Err() != nil {
			return nil, scanCtx.Err()
		}
		// Otherwise, the scan finished without finding anything.
		return nil, errors.New("scan finished with no working IPs found")
	}

	// Success: return the found IPs (up to the desired count).
	count := len(ipList)
	if count > desiredIPs {
		count = desiredIPs
	}
	return ipList[:count], nil
}

func APIStartProxy(ctx context.Context, l *slog.Logger, tnet *netstack.Net, bindAddress netip.AddrPort) (netip.AddrPort, error) {
	ln, err := net.Listen("tcp", bindAddress.String())
	if err != nil {
		return netip.AddrPort{}, err // Return error if binding was unsuccessful
	}

	vt := VirtualTun{
		Tnet:   tnet,
		Logger: l.With("subsystem", "vtun"),
		Dev:    nil,
		Ctx:    ctx,
		pool:   buf.DefaultAllocator,
	}

	proxy := mixed.NewProxy(
		mixed.WithListener(ln),
		mixed.WithLogger(l),
		mixed.WithContext(ctx),
		mixed.WithUserHandler(func(request *statute.ProxyRequest) error {
			return vt.generalHandler(request)
		}),
	)
	go func() {
		_ = proxy.ListenAndServe()
	}()
	go func() {
		<-vt.Ctx.Done()
		vt.Stop()
		ln.Close()
	}()

	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				debug.FreeOSMemory()
			case <-ctx.Done():
				return
			}
		}
	}()

	return ln.Addr().(*net.TCPAddr).AddrPort(), nil
}

var APIBuffSize = 24576
var connMutex sync.Mutex
var maxConcurrent = 100
var connTimeouts = make(map[net.Conn]time.Time)

func (vt *VirtualTun) APIgeneralHandler(req *statute.ProxyRequest) error {
	connMutex.Lock()

	if len(connTimeouts) >= maxConcurrent {
		var oldestConn net.Conn
		var oldestTime time.Time

		for conn, timestamp := range connTimeouts {
			if oldestConn == nil || timestamp.Before(oldestTime) {
				oldestConn = conn
				oldestTime = timestamp
			}
		}

		if oldestConn != nil {
			vt.Logger.Info("dropping oldest connection to make room for new one")
			oldestConn.Close()
			delete(connTimeouts, oldestConn)
		}
	}

	connTimeouts[req.Conn] = time.Now()
	connMutex.Unlock()

	defer func() {
		connMutex.Lock()
		delete(connTimeouts, req.Conn)
		connMutex.Unlock()
	}()

	vt.Logger.Debug("handling connection", "protocol", req.Network, "destination", req.Destination)
	conn, err := vt.Tnet.Dial(req.Network, req.Destination)
	if err != nil {
		return err
	}

	timeout := 15 * time.Second
	switch req.Network {
	case "udp", "udp4", "udp6":
		timeout = 15 * time.Second
	}

	// Channel to notify when copy operation is done
	done := make(chan error, 2)

	// Copy data from req.Conn to conn
	go func() {
		buf1 := vt.pool.Get(APIBuffSize)
		defer func(pool buf.Allocator, buf []byte) {
			_ = pool.Put(buf)
		}(vt.pool, buf1)
		_, err := copyConnTimeout(conn, req.Conn, buf1, timeout)
		done <- err
	}()

	// Copy data from conn to req.Conn
	go func() {
		buf2 := vt.pool.Get(APIBuffSize)
		defer func(pool buf.Allocator, buf []byte) {
			_ = pool.Put(buf)
		}(vt.pool, buf2)
		_, err := copyConnTimeout(req.Conn, conn, buf2, timeout)
		done <- err
	}()

	// Wait for one of the copy operations to finish
	err = <-done
	if err != nil {
		vt.Logger.Warn(err.Error())
	}

	// Close connections to unblock the other copy operation then wait for it to finish.
	conn.Close()
	req.Conn.Close()
	<-done
	return nil
}
