package xdp

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf xdp.c -- -O2 -Wall

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf/link"
)

// Blocker defines the interface for an IP blocker (like XDP).
type Blocker interface {
	BlockIP(ipStr string) error
	UnblockIP(ipStr string) error
	GetStats() (Stats, error)
	Close() error
}

type Stats struct {
	Allowed uint64
	Blocked uint64
}

type XDPBlocker struct {
	objs bpfObjects
	l    link.Link
}

// InitXDP initializes the XDP program on the specified network interface.
func InitXDP(ifaceName string) (*XDPBlocker, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface %s: %w", ifaceName, err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("failed to load BPF objects: %w", err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpDropFunc,
		Interface: iface.Index,
	})
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("failed to attach XDP to %s: %w", ifaceName, err)
	}

	return &XDPBlocker{
		objs: objs,
		l:    l,
	}, nil
}

// BlockIP adds an IP to the XDP blocklist.
func (x *XDPBlocker) BlockIP(ipStr string) error {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return fmt.Errorf("invalid IPv4 address: %s", ipStr)
	}

	// Convert IP to uint32 (network byte order as received from ip->saddr)
	var key uint32
	// ip is [4]byte. ip->saddr in C receives bytes in network order (Big Endian)
	// But actually, we just need to match the byte representation.
	key = uint32(ip[0]) | uint32(ip[1])<<8 | uint32(ip[2])<<16 | uint32(ip[3])<<24

	var value uint8 = 1
	return x.objs.Blocklist.Put(key, value)
}

// UnblockIP removes an IP from the XDP blocklist.
func (x *XDPBlocker) UnblockIP(ipStr string) error {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return fmt.Errorf("invalid IPv4 address: %s", ipStr)
	}

	var key uint32
	key = uint32(ip[0]) | uint32(ip[1])<<8 | uint32(ip[2])<<16 | uint32(ip[3])<<24

	return x.objs.Blocklist.Delete(key)
}

// GetStats returns the current XDP block/allow statistics.
func (x *XDPBlocker) GetStats() (Stats, error) {
	var stats Stats
	key := uint32(0)
	err := x.objs.XdpStats.Lookup(key, &stats)
	return stats, err
}

// Close removes the XDP program and closes BPF maps.
func (x *XDPBlocker) Close() error {
	var err1, err2 error
	if x.l != nil {
		err1 = x.l.Close()
	}
	err2 = x.objs.Close()

	if err1 != nil {
		return err1
	}
	return err2
}
