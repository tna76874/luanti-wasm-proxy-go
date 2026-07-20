package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"sync/atomic"

	"luantiproxy/internal"

	"github.com/gorilla/websocket"
)

var (
	activeClients int64
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		allowed := internal.GlobalConfig.AllowedOrigins
		origin := r.Header.Get("Origin")

		if len(allowed) == 0 {
			return true
		}

		for _, allowedOrigin := range allowed {
			if allowedOrigin == "*" || origin == allowedOrigin {
				return true
			}
		}
		
		internal.LogToFile("[BLOCKED] Access denied for %s: Origin '%s' not allowed", r.RemoteAddr, origin)
		return false
	},
}

func main() {
	configPath := flag.String("config", "config.yml", "Path to configuration file")
	flag.Parse()

	internal.LoadConfig(*configPath)

	vpnStatus := "DISABLED"
	if internal.GlobalConfig.EnableVPN {
		vpnStatus = "ENABLED"
	}
	internal.LogToFile("[STARTUP] VPN functionality is currently: %s", vpnStatus)
	internal.LogToFile("[STARTUP] Max clients limit configured to: %d", internal.GlobalConfig.MaxClients)

	var connId int32

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		remoteAddr := r.RemoteAddr
		origin := r.Header.Get("Origin")
		internal.LogToFile("[CONNECT] Incoming connection attempt from %s with Origin: '%s'", remoteAddr, origin)

		if internal.GlobalConfig.ForceSSL {
			isSecure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
			if !isSecure {
				internal.LogToFile("[BLOCKED] Access denied for %s (Insecure connection, HTTPS/SSL required)", remoteAddr)
				http.Error(w, "Access Denied - SSL Required", http.StatusForbidden)
				return
			}
		}

		if !internal.CheckSourceAllowed(remoteAddr, internal.GlobalConfig.AllowedSources) {
			internal.LogToFile("[BLOCKED] Access denied for %s (Source IP not allowed)", remoteAddr)
			http.Error(w, "Access Denied", http.StatusForbidden)
			return
		}

		if !internal.CheckTimeAllowed() {
			internal.LogToFile("[BLOCKED] Access denied for %s (Outside allowed day/time schedule)", remoteAddr)
			http.Error(w, "Access Denied - Outside Play Schedule", http.StatusForbidden)
			return
		}

		maxAllowed := internal.GlobalConfig.MaxClients
		if maxAllowed <= 0 {
			maxAllowed = 100
		}

		if atomic.LoadInt64(&activeClients) >= int64(maxAllowed) {
			internal.LogToFile("[BLOCKED] Connection rejected for %s: Max clients limit (%d) reached.", remoteAddr, maxAllowed)
			http.Error(w, "Service Unavailable (Max clients reached)", http.StatusServiceUnavailable)
			return
		}

		socket, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("Upgrade error (Origin check failed or invalid handshake): %v", err)
			return
		}

		atomic.AddInt64(&activeClients, 1)

		id := int(atomic.AddInt32(&connId, 1))
		headers := make(map[string][]string)
		for k, v := range r.Header {
			headers[k] = v
		}

		go func() {
			defer atomic.AddInt64(&activeClients, -1)
			internal.NewClient(id, socket, remoteAddr, headers)
		}()
	})

	addr := fmt.Sprintf(":%d", internal.GlobalConfig.Port)
	log.Printf("Proxy listening on port %d", internal.GlobalConfig.Port)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
