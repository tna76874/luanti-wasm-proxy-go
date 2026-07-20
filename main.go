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
	CheckOrigin: func(r *http.Request) bool { return true },
}

func main() {
	configPath := flag.String("config", "config.yml", "Path to configuration file")
	flag.Parse()

	internal.LoadConfig(*configPath)

	var connId int32

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		remoteAddr := r.RemoteAddr

		if !internal.CheckSourceAllowed(remoteAddr, internal.GlobalConfig.AllowedSources) {
			log.Printf("Access denied for %s (Source IP not allowed)", remoteAddr)
			http.Error(w, "Access Denied", http.StatusForbidden)
			return
		}

		if !internal.CheckTimeAllowed() {
			log.Printf("Access denied for %s (Outside allowed day/time schedule)", remoteAddr)
			http.Error(w, "Access Denied - Outside Play Schedule", http.StatusForbidden)
			return
		}

		socket, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("Upgrade error: %v", err)
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
