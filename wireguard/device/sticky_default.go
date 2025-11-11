//go:build !linux

package device

import (
	"github.com/linsernottaken/warp-plus/wireguard/conn"
	"github.com/linsernottaken/warp-plus/wireguard/rwcancel"
)

func (device *Device) startRouteListener(bind conn.Bind) (*rwcancel.RWCancel, error) {
	return nil, nil
}
