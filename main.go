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

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		// Wenn keine Allowed Origins konfiguriert sind, Check überspringen (True)
		allowed := internal.GlobalConfig.AllowedOrigins
		if len(allowed) == 0 {
			return true
		}

		origin := r.Header.Get("Origin")
		for _, allowedOrigin := range allowed {
			if allowedOrigin == "*" || origin == allowedOrigin {
				return true
			}
		}
		return false
	},
}

func main() {
	configPath := flag.String("config", "config.yml", "Path to configuration file")
	flag.Parse()

	internal.LoadConfig(*configPath)

	var connId int32

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		remoteAddr := r.RemoteAddr

		// SSL erzwingen Prüfung (unterstützt direktes HTTPS oder X-Forwarded-Proto vom Reverse Proxy)
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

		socket, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("Upgrade error (Origin check failed or invalid handshake): %v", err)
			return
		}

		id := int(atomic.AddInt32(&connId, 1))
		headers := make(map[string][]string)
		for k, v := range r.Header {
			headers[k] = v
		}

		internal.NewClient(id, socket, remoteAddr, headers)
	})

	addr := fmt.Sprintf(":%d", internal.GlobalConfig.Port)
	log.Printf("Proxy listening on port %d", internal.GlobalConfig.Port)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
