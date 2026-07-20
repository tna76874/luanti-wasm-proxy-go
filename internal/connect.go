package internal

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type ConnectProxy struct {
	client    *Client
	firstLine bool
}

func NewConnectProxy(client *Client) *ConnectProxy {
	return &ConnectProxy{
		client:    client,
		firstLine: true,
	}
}

const connectionEstablishedReply = "HTTP/1.0 200 Connection Established\r\nProxy-agent: Apache/2.4.41 (Ubuntu)\r\n\r\n"

const geoipResponseTpl = "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nDate: %s\r\nContent-Type: application/json\r\nContent-Length: 19\r\nConnection: keep-alive\r\nCache-Control: max-age=604800, private\r\nAccess-Control-Allow-Origin: *\r\n\r\n{\"continent\":\"NA\"}"

const listResponseTpl = "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nDate: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nLast-Modified: %s\r\nConnection: keep-alive\r\nAccess-Control-Allow-Origin: *\r\n\r\n%s"

type ServerListEntry struct {
	Address  string `json:"address"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	ProtoMin int    `json:"proto_min"`
	ProtoMax int    `json:"proto_max"`
}

type ServerListPayload struct {
	Total    map[string]int    `json:"total"`
	TotalMax map[string]int    `json:"total_max"`
	List     []ServerListEntry `json:"list"`
}

func (cp *ConnectProxy) Forward(data []byte, isBinary bool) {
	if cp.firstLine {
		cp.firstLine = false
		cp.handleHandshake(data)
		return
	}
	if !isBinary {
		cp.client.Log("ConnectProxy received non-binary messages")
		cp.Close()
		return
	}

	reqStr := string(data)
	if !strings.HasSuffix(reqStr, "\r\n\r\n") {
		return
	}

	lines := strings.Split(reqStr, "\r\n")
	if len(lines) < 1 {
		cp.Close()
		return
	}

	tokens := strings.Split(lines[0], " ")
	if len(tokens) < 2 || tokens[0] != "GET" {
		cp.Close()
		return
	}

	url := Sanitize(tokens[1])
	nowStr := time.Now().UTC().Format(time.RFC1123)

	var response string
	if strings.HasPrefix(url, "/geoip") {
		response = fmt.Sprintf(geoipResponseTpl, nowStr)
	} else if strings.HasPrefix(url, "/list") {
		var listEntries []ServerListEntry
		for _, rule := range GlobalConfig.DirectProxies {
			listEntries = append(listEntries, ServerListEntry{
				Address:  rule.VirtualIP,
				IP:       rule.VirtualIP,
				Port:     30000,
				ProtoMin: 37,
				ProtoMax: 42,
			})
		}

		payloadObj := ServerListPayload{
			Total:    map[string]int{"servers": len(listEntries), "clients": 0},
			TotalMax: map[string]int{"server": len(listEntries), "clients": 0},
			List:     listEntries,
		}

		payloadBytes, err := json.Marshal(payloadObj)
		if err != nil {
			cp.client.Log("Failed to marshal server list: " + err.Error())
			cp.Close()
			return
		}
		
		response = fmt.Sprintf(
			listResponseTpl,
			nowStr,
			len(payloadBytes),
			nowStr,
			string(payloadBytes),
		)
		cp.client.Log("Sending virtual server list")
	} else {
		cp.client.Log(fmt.Sprintf("Invalid GET request for %s", url))
		cp.Close()
		return
	}

	cp.client.Send([]byte(response), true)
}

func (cp *ConnectProxy) handleHandshake(data []byte) {
	reqStr := string(data)
	lines := strings.Split(reqStr, "\r\n")
	if len(lines) < 1 {
		cp.Close()
		return
	}

	tokens := strings.Split(lines[0], " ")
	if len(tokens) != 3 || tokens[0] != "CONNECT" || tokens[2] != "HTTP/1.1" {
		cp.Close()
		return
	}

	hostPort := strings.Split(tokens[1], ":")
	if len(hostPort) != 2 {
		cp.Close()
		return
	}

	host := hostPort[0]
	if host != "servers.minetest.net" {
		cp.client.Log(fmt.Sprintf("Ignoring request to proxy to %s", tokens[1]))
		cp.Close()
		return
	}

	cp.client.Log("Connected for server list")
	cp.client.Send([]byte(connectionEstablishedReply), true)
}

func (cp *ConnectProxy) Close() {
	cp.client.Close()
}
