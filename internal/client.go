package internal

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type Client struct {
	id             int
	socket         *websocket.Conn
	ipChain        []string
	target         Target
	mu             sync.Mutex
	lastLog        string
	lastCount      int
	tokens         float64
	lastTokenCheck time.Time
	timer          *time.Timer
	pingTicker     *time.Ticker
	stopPing       chan struct{}
}

const (
	maxBurst       = 5000.0
	refillRate     = 2000.0
	pongWait       = 60 * time.Second
	pingPeriod     = (pongWait * 9) / 10
)

func NewClient(id int, socket *websocket.Conn, remoteAddr string, headers map[string][]string) *Client {
	socket.SetReadLimit(65536)

	timeoutDur, err := time.ParseDuration(GlobalConfig.ConnectionTimeout)
	if err != nil {
		timeoutDur = 1 * time.Hour
	}

	c := &Client{
		id:             id,
		socket:         socket,
		ipChain:        ExtractIPChain(headers, remoteAddr),
		tokens:         maxBurst,
		lastTokenCheck: time.Now(),
		stopPing:       make(chan struct{}),
	}

	c.mu.Lock()
	c.timer = time.AfterFunc(timeoutDur, func() {
		c.Log("[TIMEOUT] Maximum connection duration reached. Closing connection.")
		c.Close()
	})
	c.mu.Unlock()
	
	originSource := remoteAddr
	if len(c.ipChain) > 0 {
		originSource = strings.Join(c.ipChain, " -> ")
	}
	log.Printf("[CLIENT %d] Connected successfully. Origin chain / Source: [%s]", c.id, originSource)
	c.Log(fmt.Sprintf("Initialized client session from origin: %v (Absolute max duration: %v)", c.ipChain, timeoutDur))

	_ = c.socket.SetReadDeadline(time.Now().Add(pongWait))
	c.socket.SetPongHandler(func(string) error {
		_ = c.socket.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	go c.pingRoutine()
	go c.readPump()
	return c
}

func (c *Client) pingRoutine() {
	c.pingTicker = time.NewTicker(pingPeriod)
	defer c.pingTicker.Stop()

	for {
		select {
		case <-c.pingTicker.C:
			c.mu.Lock()
			if c.socket == nil {
				c.mu.Unlock()
				return
			}
			_ = c.socket.SetWriteDeadline(time.Now().Add(10 * time.Second))
			err := c.socket.WriteMessage(websocket.PingMessage, nil)
			c.mu.Unlock()
			if err != nil {
				return
			}
		case <-c.stopPing:
			return
		}
	}
}

func (c *Client) Log(args ...interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	line := fmt.Sprintf("[CLIENT %d] %s", c.id, fmt.Sprint(args...))
	if c.lastLog != line {
		if c.lastCount > 0 {
			log.Printf("%s [repeated %d times]", c.lastLog, c.lastCount)
		}
		LogToFile(line)
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
	
	_ = c.socket.SetWriteDeadline(time.Now().Add(10 * time.Second))

	msgType := websocket.TextMessage
	if binary {
		msgType = websocket.BinaryMessage
	}
	_ = c.socket.WriteMessage(msgType, data)
}

func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	select {
	case <-c.stopPing:
	default:
		close(c.stopPing)
	}

	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
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

		c.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(c.lastTokenCheck).Seconds()
		c.lastTokenCheck = now

		c.tokens += elapsed * refillRate
		if c.tokens > maxBurst {
			c.tokens = maxBurst
		}

		exceeded := false
		if c.tokens < 1.0 {
			exceeded = true
		} else {
			c.tokens -= 1.0
		}
		c.mu.Unlock()

		if exceeded {
			c.Log("[BLOCKED] Client exceeded message rate limit / burst quota (Spam detected). Closing connection.")
			return
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
		if !GlobalConfig.EnableVPN {
			c.Log("[BLOCKED] MAKEVPN requested but VPN is disabled in config.")
			c.Close()
			return
		}
		if len(tokens) < 2 {
			return
		}
		game := tokens[1]
		sCode, cCode := VpnMake(game)
		response = fmt.Sprintf("NEWVPN %s %s", sCode, cCode)

	case "VPN":
		if !GlobalConfig.EnableVPN {
			c.Log("[BLOCKED] VPN requested but VPN is disabled in config.")
			c.Close()
			return
		}
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
