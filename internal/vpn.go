package internal

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"sync"
	"time"
)

func randVpnCode() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

var (
	vpnMap   = make(map[string]*VPN)
	vpnMutex sync.Mutex
)

type VPN struct {
	ServerCode   string
	ClientCode   string
	Targets      map[string]*VPNTarget
	mu           sync.Mutex
	lastActivity time.Time
}

func init() {
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		for range ticker.C {
			vpnMutex.Lock()
			now := time.Now()
			seen := make(map[*VPN]bool)
			for _, v := range vpnMap {
				if seen[v] {
					continue
				}
				seen[v] = true

				v.mu.Lock()
				inactive := now.Sub(v.lastActivity) > 2*time.Hour
				v.mu.Unlock()

				if inactive {
					delete(vpnMap, v.ServerCode)
					delete(vpnMap, v.ClientCode)
				}
			}
			vpnMutex.Unlock()
		}
	}()
}

func VpnMake(game string) (string, string) {
	vpnMutex.Lock()
	defer vpnMutex.Unlock()

	now := time.Now()
	v := &VPN{
		ServerCode:   randVpnCode(),
		ClientCode:   randVpnCode(),
		Targets:      make(map[string]*VPNTarget),
		lastActivity: now,
	}
	vpnMap[v.ServerCode] = v
	vpnMap[v.ClientCode] = v
	return v.ServerCode, v.ClientCode
}

func VpnConnect(client *Client, code string, bindPort int) Target {
	vpnMutex.Lock()
	v, exists := vpnMap[code]
	if exists {
		v.mu.Lock()
		v.lastActivity = time.Now()
		v.mu.Unlock()
	}
	vpnMutex.Unlock()

	if !exists {
		return nil
	}
	return NewVPNTarget(v, client, code, bindPort)
}

type VPNTarget struct {
	vpn      *VPN
	client   *Client
	bindPort int
	ip       string
	addr     string
}

func NewVPNTarget(v *VPN, client *Client, code string, bindPort int) *VPNTarget {
	var ip string
	if code == v.ServerCode {
		ip = "172.16.0.1"
	} else if code == v.ClientCode {
		bBig, _ := rand.Int(rand.Reader, big.NewInt(16))
		b := bBig.Int64() + 16
		cBig, _ := rand.Int(rand.Reader, big.NewInt(253))
		c := cBig.Int64() + 1
		dBig, _ := rand.Int(rand.Reader, big.NewInt(253))
		d := dBig.Int64() + 1
		ip = fmt.Sprintf("172.%d.%d.%d", b, c, d)
	}

	addr := fmt.Sprintf("%s:%d", ip, bindPort)
	vt := &VPNTarget{
		vpn:      v,
		client:   client,
		bindPort: bindPort,
		ip:       ip,
		addr:     addr,
	}

	v.mu.Lock()
	v.Targets[addr] = vt
	v.lastActivity = time.Now()
	v.mu.Unlock()

	client.Log(fmt.Sprintf("VPN connect to %s", addr))
	return vt
}

func (vt *VPNTarget) Forward(data []byte, isBinary bool) {
	const epMagic = 0x778B4CF3
	if len(data) < 12 {
		return
	}
	magic := ReadUint32(data, 0)
	if magic != epMagic {
		return
	}

	destIP := InetNtop(data[4:8])
	destPort := ReadUint16(data, 8)
	pktLen := ReadUint16(data, 10)

	if len(data) != 12+int(pktLen) {
		return
	}

	vt.vpn.mu.Lock()
	vt.vpn.lastActivity = time.Now()
	remote, exists := vt.vpn.Targets[fmt.Sprintf("%s:%d", destIP, destPort)]
	vt.vpn.mu.Unlock()

	if !exists {
		vt.client.Log(fmt.Sprintf("%s -> %s:%d (dropped)", vt.addr, destIP, destPort))
		return
	}

	vt.client.Log(fmt.Sprintf("%s -> %s", vt.addr, remote.addr))

	copy(data[4:8], InetPton(vt.ip))
	data[8] = byte(vt.bindPort >> 8)
	data[9] = byte(vt.bindPort & 0xFF)

	remote.client.Send(data, true)
}

func (vt *VPNTarget) Close() {
	vt.vpn.mu.Lock()
	delete(vt.vpn.Targets, vt.addr)
	isEmpty := len(vt.vpn.Targets) == 0
	vt.vpn.mu.Unlock()

	if isEmpty {
		vpnMutex.Lock()
		vt.vpn.mu.Lock()
		// Double-Check unter globalem Lock, ob währenddessen wieder Targets dazugekommen sind
		if len(vt.vpn.Targets) == 0 {
			delete(vpnMap, vt.vpn.ServerCode)
			delete(vpnMap, vt.vpn.ClientCode)
		}
		vt.vpn.mu.Unlock()
		vpnMutex.Unlock()
	}

	vt.client.Close()
}
