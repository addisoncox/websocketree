# Websocketree

Simple websocket server library

```go
	handler := func(msg []byte) []byte {
		return msg
	}
	config := websocketree.WebSocketServerConfig{
		OnMessageHandler: handler,
	}
	wsEchoServer := websocketree.NewWebSocketServer("127.0.0.1:9000")
	wsEchoServer.Config(config)
	wsEchoServer.Run()
```