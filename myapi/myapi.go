package myapi

import "github.com/linsernottaken/warp-plus/warp"

var WarpPrefixes = warp.APIWarpPrefixes
var WarpPorts = warp.APIGetWarpPorts

type Identity = warp.Identity

var LoadOrCreateIdentity = warp.APILoadOrCreateIdentity

var RandomWarpPrefix = warp.APIRandomWarpPrefix
var RandomWarpEndpoint = warp.APIRandomWarpEndpoint
