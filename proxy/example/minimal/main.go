package main

import (
	"github.com/linsernottaken/warp-plus/proxy/pkg/mixed"
)

func main() {
	proxy := mixed.NewProxy()
	_ = proxy.ListenAndServe()
}
