package main

import "github.com/addisoncox/websocketree"

func main() {
	handler := func(msg []byte) []byte {
		return msg
	}
	config := websocketree.WebSocketServerConfig{
		OnMessageHandler: handler,
	}
	wsEchoServer := websocketree.NewWebSocketServer("0.0.0.0:9000")
	wsEchoServer.Config(config)
	wsEchoServer.Run()
}
