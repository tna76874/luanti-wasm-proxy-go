package internal

import (
	"fmt"
	"net"
	"sync"
)

type Target interface {
	Forward(data []byte, isBinary bool)
	Close()
}

type UDPProxy struct {
	client    *Client
	conn      *net.UDPConn
	realIP    string
	realPort  int
	sendOk    bool
	sendQueue [][]byte
	mu        sync.Mutex
}

func NewUDPProxy(client *Client, ip string, port int) *UDPProxy {
	rAddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		client.Log("Failed to resolve UDP target: " + err.Error())
		return nil
	}

	conn, err := net.DialUDP("udp4", nil, rAddr)
	if err != nil {
		client.Log("Failed to bind UDP socket: " + err.Error())
		return nil
	}

	p := &UDPProxy{
		client:   client,
		conn:     conn,
		realIP:   ip,
		realPort: port,
		sendOk:   true,
	}

	go p.readLoop()
	return p
}

func (u *UDPProxy) Forward(data []byte, isBinary bool) {
	if len(data) < 4 || data[0] != 0x4f || data[1] != 0x45 || data[2] != 0x74 || data[3] != 0x03 {
		u.client.Log("Client sent packet with invalid protocol.")
		return
	}

	u.mu.Lock()
	send := u.sendOk
	if send {
		u.mu.Unlock()
		_, _ = u.conn.Write(data)
	} else {
		u.sendQueue = append(u.sendQueue, data)
		u.mu.Unlock()
	}
}

func (u *UDPProxy) readLoop() {
	buf := make([]byte, 65535)
	for {
		n, err := u.conn.Read(buf)
		if err != nil {
			break
		}
		dataCopy := make([]byte, n)
		copy(dataCopy, buf[:n])
		u.client.Send(dataCopy, true)
	}
}

func (u *UDPProxy) Close() {
	if u.conn != nil {
		u.conn.Close()
	}
}
