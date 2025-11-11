package warp

import (
	"math/rand"
	"net/netip"
	"time"

	"github.com/linsernottaken/warp-plus/iputils"
)

func APIWarpPrefixes() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("162.158.192.0/24"),
		//netip.MustParsePrefix("162.158.0.0/15"),
		//netip.MustParsePrefix("188.114.96.0/20"),
		//netip.MustParsePrefix("8.40.28.0/24"),
		//netip.MustParsePrefix("8.6.112.0/24"),
		//netip.MustParsePrefix("8.39.204.0/24"),
		//netip.MustParsePrefix("8.39.125.0/24"),
		//netip.MustParsePrefix("8.35.211.0/24"),
		//netip.MustParsePrefix("8.34.146.0/24"),
		//netip.MustParsePrefix("8.34.70.0/24"),
		//netip.MustParsePrefix("8.39.214.0/24"),
		//netip.MustParsePrefix("8.47.69.0/24"),
		//netip.MustParsePrefix("23.227.37.0/24"),
		netip.MustParsePrefix("2606:4700:d0::/64"),
		netip.MustParsePrefix("2606:4700:d1::/64"),
	}
}

func APIGetWarpPorts() []uint16 {
	return []uint16{
		500,
		// 854,
		// 859,
		// 864,
		// 878,
		// 880,
		// 890,
		// 891,
		// 894,
		// 903,
		908,
		// 928,
		// 934,
		// 939,
		// 942,
		// 943,
		// 945,
		// 946,
		// 955,
		// 968,
		// 987,
		// 988,
		// 995,
		// 1002,
		// 1010,
		// 1014,
		// 1018,
		// 1070,
		// 1074,
		// 1180,
		// 1387,
		1701,
		// 1843,
		// 2371,
		2408,
		// 2506,
		// 3138,
		// 3476,
		// 3581,
		// 3854,
		//4177,
		//4198,
		//4233,
		4500,
		//5279,
		//5956,
		//7103,
		//7152,
		//7156,
		//7281,
		//7559,
		//8319,
		//8742,
		//8854,
		//8886,
	}
}

type APIIdentity = Identity

var APILoadOrCreateIdentity = LoadOrCreateIdentity

func APIRandomWarpPrefix(v4, v6 bool) netip.Prefix {
	if !v4 && !v6 {
		panic("Must choose a IP version for RandomWarpPrefix")
	}

	cidrs := WarpPrefixes()
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	for {
		cidr := cidrs[rng.Intn(len(cidrs))]

		if v4 && cidr.Addr().Is4() {
			return cidr
		}

		if v6 && cidr.Addr().Is6() {
			return cidr
		}
	}
}

func APIRandomWarpEndpoint(v4, v6 bool) (netip.AddrPort, error) {
	randomIP, err := iputils.RandomIPFromPrefix(APIRandomWarpPrefix(v4, v6))
	if err != nil {
		return netip.AddrPort{}, err
	}

	return netip.AddrPortFrom(randomIP, RandomWarpPort()), nil
}
