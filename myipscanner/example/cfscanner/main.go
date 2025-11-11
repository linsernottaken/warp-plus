package main

import (
	"context"

	"github.com/bepass-org/warp-plus/myipscanner"
)

func main() {
	// new scanner
	scanner := myipscanner.NewScanner(
		// ipscanner.WithHTTPPing(),
		myipscanner.WithUseIPv6(true),
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go scanner.Run(ctx)

	<-ctx.Done()
}
