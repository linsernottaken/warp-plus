package main

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/bepass-org/warp-plus/myipscanner"
	"github.com/bepass-org/warp-plus/myipscanner/internal/statute"
	"github.com/bepass-org/warp-plus/warp"
	"github.com/fatih/color"
	"github.com/rodaine/table"
)

var (
	privKey           = "yGXeX7gMyUIZmK5QIgC7+XX5USUSskQvBYiQ6LdkiXI="
	pubKey            = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
	googlev6DNSAddr80 = netip.MustParseAddrPort("[2001:4860:4860::8888]:80")
)

func canConnectIPv6(remoteAddr netip.AddrPort) bool {
	dialer := net.Dialer{
		Timeout: 5 * time.Second,
	}

	conn, err := dialer.Dial("tcp6", remoteAddr.String())
	if err != nil {
		return false
	}
	defer conn.Close()

	return true
}

func RunScan(privKey, pubKey string) (result []statute.IPInfo) {
	const desiredIPs = 1
	scanner := myipscanner.NewScanner(
		myipscanner.WithLogger(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))),
		// ipscanner.WithWarpPing(),
		myipscanner.WithWarpPrivateKey(privKey),
		myipscanner.WithWarpPeerPublicKey(pubKey),
		myipscanner.WithUseIPv6(canConnectIPv6(googlev6DNSAddr80)),
		myipscanner.WithUseIPv4(true),
		myipscanner.WithMaxDesirableRTT(500*time.Millisecond),
		myipscanner.WithCidrList(warp.APIWarpPrefixes()),
		myipscanner.WithConcurrentScanners(200),
		myipscanner.WithCustomEndpoints([]string{"188.114.98.75:987"}),
		myipscanner.WithStopOnFirstGoodIPs(desiredIPs),
		//ipscanner.WithDeepScan(true),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// scanner.Run is now blocking, so we run it in a goroutine
	scanDone := make(chan struct{})
	go func() {
		defer close(scanDone)
		scanner.Run(ctx)
	}()

	t := time.NewTicker(250 * time.Millisecond)
	defer t.Stop()

	for {
		select {
		case <-scanDone: // The scan finished on its own (target count, deep scan done, etc.)
			slog.Info("Scan finished. Collecting results.")
			result = scanner.GetAvailableIPs()
			return
		case <-ctx.Done(): // The application's main context timed out or was cancelled.
			slog.Info("Context done. Collecting results.")
			result = scanner.GetAvailableIPs()
			return
		case <-t.C:
			// Continuously check for results without blocking.
			ipList := scanner.GetAvailableIPs()
			// This check is optional but can allow for early exit if desired.
			if len(ipList) >= desiredIPs {
				slog.Info("Desired number of IPs found. Exiting.")
				result = ipList
				return
			}
			continue
		}
	}
}

func main() {
	result := RunScan(privKey, pubKey)

	headerFmt := color.New(color.FgGreen, color.Underline).SprintfFunc()
	columnFmt := color.New(color.FgYellow).SprintfFunc()

	tbl := table.New("Address", "RTT (ping)", "Time")
	tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)

	for _, info := range result {
		tbl.AddRow(info.AddrPort, info.RTT, info.CreatedAt)
	}

	tbl.Print()
}
