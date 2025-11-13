package myapi

import (
	"github.com/linsernottaken/warp-plus/myipscanner"
	"github.com/linsernottaken/warp-plus/warp"
)

// //////////// warp package
type Identity = warp.Identity

var WarpPrefixes = warp.APIWarpPrefixes
var WarpPorts = warp.APIGetWarpPorts
var LoadOrCreateIdentity = warp.APILoadOrCreateIdentity
var RandomWarpPrefix = warp.APIRandomWarpPrefix
var RandomWarpEndpoint = warp.APIRandomWarpEndpoint

// //////////// ipscanner package
type IPScanner = myipscanner.IPScanner
type Option = myipscanner.Option
type IPInfo = myipscanner.IPInfo

var WithLogger = myipscanner.WithLogger
var WithWarpPrivateKey = myipscanner.WithWarpPrivateKey
var WithWarpPeerPublicKey = myipscanner.WithWarpPeerPublicKey
var WithWarpPreSharedKey = myipscanner.WithWarpPreSharedKey
var WithUseIPv4 = myipscanner.WithUseIPv4
var WithUseIPv6 = myipscanner.WithUseIPv6
var WithMaxDesirableRTT = myipscanner.WithMaxDesirableRTT
var WithTCPPingFilterRTT = myipscanner.WithTCPPingFilterRTT
var WithBucketSize = myipscanner.WithBucketSize
var WithConcurrentScanners = myipscanner.WithConcurrentScanners
var WithScanTimeout = myipscanner.WithScanTimeout
var WithStopOnFirstGoodIPs = myipscanner.WithStopOnFirstGoodIPs
var WithTestEndpointPorts = myipscanner.WithTestEndpointPorts
var WithCidrList = myipscanner.WithCidrList
var WithCustomEndpoints = myipscanner.WithCustomEndpoints
var NewScanner = myipscanner.NewScanner
