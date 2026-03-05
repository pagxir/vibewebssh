package main

import (
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"

	"golang.org/x/net/websocket"
)

func main() {
	cert, err := tls.LoadX509KeyPair(
		"/home/level/.acme.sh/claw.603030.xyz_ecc/fullchain.cer",
		"/home/level/.acme.sh/claw.603030.xyz_ecc/claw.603030.xyz.key",
	)
	if err != nil {
		log.Fatal("load cert:", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
	}

	dir, err := os.Getwd()
	if err != nil {
		log.Fatal("getwd:", err)
	}
	log.Printf("Serving files from: %s", dir)

	wsHandler := func(w http.ResponseWriter, r *http.Request) {
		log.Printf("WebSocket request: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		host := r.URL.Query().Get("host")
		port := r.URL.Query().Get("port")
		log.Printf("Target: host=%s port=%s", host, port)
		handler := websocket.Handler(func(ws *websocket.Conn) {
			defer ws.Close()
			ws.PayloadType = websocket.BinaryFrame
			log.Printf("WebSocket handler started for %s:%s", host, port)
			if host == "" || port == "" {
				log.Printf("missing host or port")
				return
			}
			portInt, err := strconv.Atoi(port)
			if err != nil || portInt <= 0 || portInt > 65535 {
				log.Printf("invalid port: %s", port)
				return
			}
			target := net.JoinHostPort(host, port)
			log.Printf("WebSocket proxy connecting to: %s", target)
			conn, err := net.Dial("tcp", target)
			if err != nil {
				log.Printf("dial %s failed: %v", target, err)
				return
			}
			defer conn.Close()
			log.Printf("Connected to %s", target)
			done := make(chan struct{}, 2)
			go func() {
				io.Copy(ws, conn)
				done <- struct{}{}
			}()
			go func() {
				io.Copy(conn, ws)
				done <- struct{}{}
			}()
			<-done
			log.Printf("Connection to %s closed", target)
		})
		handler.ServeHTTP(w, r)
	}

	http.HandleFunc("/websockify", wsHandler)
	http.HandleFunc("/openclaw", wsHandler)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Request: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		if r.TLS != nil {
			log.Printf("TLS Version: %x, ServerName: %s", r.TLS.Version, r.TLS.ServerName)
		}
		http.ServeFile(w, r, "."+r.URL.Path)
	})

	listener, err := tls.Listen("tcp", ":8443", tlsConfig)
	if err != nil {
		log.Fatal("listen:", err)
	}

	log.Println("HTTPS Backend Server running on :8443")
	log.Fatal(http.Serve(listener, nil))
}
