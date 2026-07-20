package internal

import (
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
)

type Client struct {
	id        int
	socket    *websocket.Conn
	ipChain   []string
	target    Target
	mu        sync.Mutex
	lastLog   string
	lastCount int
}

func NewClient(id int, socket *websocket.Conn, remoteAddr string, headers map[string][]string) *Client {
	c := &Client{
		id:      id,
		socket:  socket,
		ipChain: ExtractIPChain(headers, remoteAddr),
	}
	
	originSource := remoteAddr
	if len(c.ipChain) > 0 {
		originSource = strings.Join(c.ipChain, " -> ")
	}
	log.Printf("[CLIENT %d] Connected successfully. Origin chain / Source: [%s]", c.id, originSource)
	c.Log(fmt.Sprintf("Initialized client session from origin: %v", c.ipChain))

	go c.readPump()
	return c
}

func (c *Client) Log(args ...interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	line := fmt.Sprintf("[CLIENT %d] %s", c.id, fmt.Sprint(args...))
	if c.lastLog != line {
		if c.lastCount > 0 {
			log.Printf("%s [repeated %d times]", c.lastLog, c.lastCount)
		}
		log.Println(line)
		c.lastLog = line
		c.lastCount = 0
	} else {
		c.lastCount++
	}
}

func (c *Client) Send(data []byte, binary bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.socket == nil {
		return
	}
	msgType := websocket.TextMessage
	if binary {
		msgType = websocket.BinaryMessage
	}
	_ = c.socket.WriteMessage(msgType, data)
}

func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.socket != nil {
		c.socket.Close()
		c.socket = nil
	}
	if c.target != nil {
		c.target.Close()
		c.target = nil
	}
}

func (c *Client) readPump() {
	defer c.Close()
	for {
		messageType, p, err := c.socket.ReadMessage()
		if err != nil {
			break
		}
		isBinary := (messageType == websocket.BinaryMessage)

		if c.target != nil {
			c.target.Forward(p, isBinary)
		} else {
			c.handleCommand(string(p))
		}
	}
}

func (c *Client) handleCommand(data string) {
	data = Sanitize(data)
	tokens := strings.Split(data, " ")
	if len(tokens) == 0 {
		return
	}
	command := tokens[0]
	var response string

	switch command {
	case "MAKEVPN":
		if len(tokens) < 2 {
			return
		}
		game := tokens[1]
		sCode, cCode := VpnMake(game)
		response = fmt.Sprintf("NEWVPN %s %s", sCode, cCode)

	case "VPN":
		if len(tokens) < 6 {
			return
		}
		code := tokens[1]
		bindPort := 0
		_, _ = fmt.Sscanf(tokens[5], "%d", &bindPort)
		c.target = VpnConnect(c, code, bindPort)
		if c.target == nil {
			c.Log("VPN connect failed")
			c.Close()
			return
		}
		response = "BIND OK"

	case "PROXY":
		if len(tokens) < 5 {
			return
		}
		isUDP := (tokens[2] == "UDP")
		ip := Sanitize(tokens[3])
		port := 0
		_, _ = fmt.Sscanf(tokens[4], "%d", &port)

		realIP, realPort, ok := MatchProxy(ip, port)
		if !ok {
			c.Log(fmt.Sprintf("Proxy to udp=%t, ip=%s, port=%d rejected", isUDP, ip, port))
			response = "PROXY FAIL"
		} else {
			if !isUDP && ip == "10.0.0.1" && port == 8080 {
				c.target = NewConnectProxy(c)
				response = "PROXY OK"
			} else if isUDP {
				c.target = NewUDPProxy(c, realIP, realPort)
				if c.target == nil {
					response = "PROXY FAIL"
				} else {
					response = "PROXY OK"
				}
			} else {
				response = "PROXY FAIL"
			}
		}
	default:
		c.Log("Unhandled command: ", data)
		c.Close()
		return
	}

	c.Send([]byte(response), false)
}
