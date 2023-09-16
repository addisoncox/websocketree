package websocketree

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"unicode/utf8"
)

const (
	websocketGUID                   = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	defaultBufferSize               = 4096
	defaultBufferPoolSize           = 10
	defaultConnectionPoolSize       = 10
	defaultPayloadInitialBufferSize = 1024
)

const (
	OpContinuation = 0x0
	OpText         = 0x1
	OpBinary       = 0x2
	OpClose        = 0x8
	OpPing         = 0x9
	OpPong         = 0xA
)

type OpCode = byte

type WebSocketConnection struct {
	conn               net.Conn
	readCh             chan []byte
	writeCh            chan WebSocketFrame
	closeCh            chan struct{}
	closeDone          chan struct{}
	compressionEnabled bool
}

type WebSocketConnPool struct {
	pool chan net.Conn
}

type WebSocketServer struct {
	addr           string
	config         WebSocketServerConfig
	connectionPool WebSocketConnPool
	bufferPool     FrameBufferPool
}

type WebSocketFrame struct {
	fin     bool
	opcode  OpCode
	payload []byte
}

type WebSocketServerConfig struct {
	OnMessageHandler       func([]byte) []byte
	OnBinaryMessageHandler func([]byte) []byte
	OnTextMessageHandler   func([]byte) []byte

	ConnectionPoolSize    int
	BufferPoolSize        int
	BufferSize            int
	DisableUtf8Validation bool
	MaskServerMessages    bool
	Logger                *log.Logger
}

func NewWebSocketServer(addr string) WebSocketServer {
	return WebSocketServer{addr: addr}
}

func (s *WebSocketServer) Config(webSocketServerConfig WebSocketServerConfig) {
	s.config = webSocketServerConfig
}

func (s *WebSocketServer) Run() {
	if s.config.ConnectionPoolSize == 0 {
		s.config.ConnectionPoolSize = defaultBufferPoolSize
	}
	if s.config.BufferPoolSize == 0 {
		s.config.BufferPoolSize = defaultBufferPoolSize
	}
	if s.config.BufferSize == 0 {
		s.config.BufferSize = defaultBufferSize
	}
	if s.config.Logger == nil {
		s.config.Logger = log.Default()
	}
	s.connectionPool = *NewWebSocketConnPool(s.config.ConnectionPoolSize)
	s.bufferPool = *NewFrameBufferPool(s.config.BufferPoolSize, s.config.BufferSize)
	http.HandleFunc("/", s.handleWebSocketUpgrade)

	err := http.ListenAndServe(s.addr, nil)
	if err != nil {
		s.config.Logger.Fatal("Error starting the server:", err)
	}
}

func NewWebSocketConnPool(size int) *WebSocketConnPool {
	return &WebSocketConnPool{
		pool: make(chan net.Conn, size),
	}
}

func (p *WebSocketConnPool) AddConnection(conn net.Conn) {
	select {
	case p.pool <- conn:
	default:
		conn.Close()
	}
}

func (p *WebSocketConnPool) GetConnection() net.Conn {
	select {
	case conn := <-p.pool:
		return conn
	default:
		return nil
	}
}

type FrameBufferPool struct {
	pool chan []byte
}

func NewFrameBufferPool(size int, bufferSize int) *FrameBufferPool {
	pool := make(chan []byte, size)
	for i := 0; i < size; i++ {
		pool <- make([]byte, bufferSize)
	}
	return &FrameBufferPool{
		pool: pool,
	}
}

func (fbp *FrameBufferPool) Get() []byte {
	select {
	case buffer := <-fbp.pool:
		return buffer
	default:
		return make([]byte, defaultBufferSize)
	}
}

func (fbp *FrameBufferPool) Put(buffer []byte) {
	select {
	case fbp.pool <- buffer:
	default:
		// If the pool is full, discard the buffer
	}
}

func webSocketCodeIsValid(code uint16) bool {
	return !((code >= 0 && code <= 999) ||
		(code >= 1004 && code <= 1006) ||
		(code >= 1015 && code <= 2999) ||
		(code >= 5000))
}

func (s *WebSocketServer) handleWebSocketUpgrade(w http.ResponseWriter, r *http.Request) {
	// Check if the request is a WebSocket upgrade request
	if !isWebSocketUpgradeRequest(r) {
		http.Error(w, "WebSocket upgrade not supported", http.StatusForbidden)
		return
	}

	// Generate the response headers for the WebSocket handshake
	responseHeaders, err := generateWebSocketHandshakeResponse(r)
	if err != nil {
		http.Error(w, "WebSocket handshake failed", http.StatusInternalServerError)
		return
	}

	// Send the HTTP 101 response with WebSocket headers to upgrade the connection
	for key, value := range responseHeaders {
		w.Header().Set(key, value)
	}
	w.WriteHeader(http.StatusSwitchingProtocols)

	conn := s.connectionPool.GetConnection()
	if conn == nil {
		// Pool is empty, create a new connection
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "WebSocket upgrade failed: connection doesn't support hijacking", http.StatusInternalServerError)
			return
		}
		var err error
		conn, _, err = hj.Hijack()
		if err != nil {
			http.Error(w, "WebSocket upgrade failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// Now the connection has been upgraded to WebSocket
	s.config.Logger.Println("WebSocket connection established!")

	// Start handling WebSocket frames asynchronously
	go s.handleWebSocket(conn)
}

func isWebSocketUpgradeRequest(r *http.Request) bool {
	// Check if the request method is GET and contains appropriate headers for WebSocket upgrade
	return r.Method == "GET" &&
		(r.Header.Get("Connection") == "Upgrade" || r.Header.Get("Connection") == "upgrade") &&
		(r.Header.Get("Upgrade") == "WebSocket" || r.Header.Get("Upgrade") == "websocket")
}

func generateWebSocketHandshakeResponse(r *http.Request) (map[string]string, error) {
	secWebSocketKey := r.Header.Get("Sec-WebSocket-Key")
	if secWebSocketKey == "" {
		return nil, fmt.Errorf("WebSocket handshake failed: Sec-WebSocket-Key not found")
	}

	concatenated := secWebSocketKey + websocketGUID
	hash := sha1.Sum([]byte(concatenated))

	secWebSocketAccept := base64.StdEncoding.EncodeToString(hash[:])

	responseHeaders := map[string]string{
		"Upgrade":              "websocket",
		"Connection":           "Upgrade",
		"Sec-WebSocket-Accept": secWebSocketAccept,
	}

	return responseHeaders, nil
}

func (s *WebSocketServer) readWebSocketFrame(conn net.Conn) (frame WebSocketFrame, frameErr error) {
	// Read the initial two bytes of the WebSocket frame to determine the opcode and mask flag

	headerStart := make([]byte, 1)
	_, err := conn.Read(headerStart)

	headerEnd := make([]byte, 1)
	_, err = conn.Read(headerEnd)
	if err != nil {
		return WebSocketFrame{}, err
	}

	if (headerStart[0] & 0x70) != 0 {
		return WebSocketFrame{}, errors.New("RSV must be 0")
	}
	// Get the opcode from the first 4 bits of the first byte
	opcode := headerStart[0] & 0xf

	// fin bit
	fin := (headerStart[0] & 0x80) != 0

	// Get the payload length and whether the frame is masked from the second byte
	mask := headerEnd[0]&0x80 != 0
	payloadLength := int(headerEnd[0] & 0x7f)

	// Handle extended payload length if indicated by payloadLength = 126 or 127
	if payloadLength == 126 {
		extendedLen := make([]byte, 2)

		_, err := conn.Read(extendedLen)

		if err != nil {
			return WebSocketFrame{}, err
		}
		payloadLength = int(extendedLen[0])<<8 | int(extendedLen[1])

	} else if payloadLength == 127 {
		extendedLen := make([]byte, 0, 8)

		for len(extendedLen) < 8 {
			octet := make([]byte, 1)
			n, err := conn.Read(octet)
			if err != nil {
				return WebSocketFrame{}, err
			} else if n != 1 {
				// Handle the case where we couldn't read a single octet
				return WebSocketFrame{}, errors.New("Unexpected EOF on read")
			}
			extendedLen = append(extendedLen, octet...)
		}

		payloadLength = 0
		for i := 0; i < 8; i++ {
			payloadLength |= int(extendedLen[i]) << uint(56-(i*8))
		}
	}

	// Read the masking key if the frame is masked
	var maskingKey []byte
	if mask {
		maskingKey = make([]byte, 0, 4)

		for len(maskingKey) < 4 {
			octet := make([]byte, 1)
			n, err := conn.Read(octet)
			if err != nil {
				return WebSocketFrame{}, err
			}
			if n != 1 {
				// Handle the case where we couldn't read a single octet
				return WebSocketFrame{}, errors.New("Unexpected EOF on read")
			}
			maskingKey = append(maskingKey, octet...)
		}
	}

	var payloadBuffer []byte
	if payloadLength < s.config.BufferSize {
		payloadBuffer = s.bufferPool.Get()
		defer s.bufferPool.Put(payloadBuffer)
	} else {
		payloadBuffer = make([]byte, payloadLength, payloadLength)
	}

	_, err = io.ReadFull(conn, payloadBuffer[:payloadLength])
	if err != nil {
		return WebSocketFrame{}, err
	}

	if mask {
		for i := 0; i < payloadLength; i++ {
			payloadBuffer[i] ^= maskingKey[i%4]
		}
	}
	return WebSocketFrame{
		fin:     fin,
		opcode:  opcode,
		payload: payloadBuffer[:payloadLength],
	}, nil
}

func (s *WebSocketServer) writeWebSocketFrame(conn net.Conn, frame *WebSocketFrame) error {

	payloadLen := len(frame.payload)

	// Always send single fragment for now
	if frame.fin {
		frame.opcode |= 0x80
	}

	// Prepare the length bytes
	var lengthBytes []byte
	if payloadLen < 126 {
		lengthBytes = []byte{byte(payloadLen)}
	} else if payloadLen <= 65535 {
		lengthBytes = []byte{126, byte(payloadLen >> 8), byte(payloadLen)}
	} else {
		lengthBytes = []byte{127, byte(payloadLen >> 56), byte(payloadLen >> 48), byte(payloadLen >> 40),
			byte(payloadLen >> 32), byte(payloadLen >> 24), byte(payloadLen >> 16), byte(payloadLen >> 8), byte(payloadLen)}
	}

	frameHeader := append([]byte{frame.opcode}, lengthBytes...)

	if s.config.MaskServerMessages {
		maskKey := make([]byte, 4)
		rand.Read(maskKey)

		frameHeader = append(frameHeader, maskKey...)

		for i := 0; i < payloadLen; i++ {
			frame.payload[i] ^= maskKey[i%4]
		}
	}

	frameLength := len(frameHeader) + payloadLen

	var frameBuffer []byte
	if frameLength > s.config.BufferSize {
		frameBuffer = make([]byte, frameLength, frameLength)
	} else {
		frameBuffer = s.bufferPool.Get()
		defer s.bufferPool.Put(frameBuffer)
	}
	copy(frameBuffer, frameHeader)
	copy(frameBuffer[len(frameHeader):], frame.payload)

	_, err := conn.Write(frameBuffer[:frameLength])
	return err
}

func (s *WebSocketServer) handleWebSocket(conn net.Conn) {
	defer conn.Close()

	readCh := make(chan []byte)
	writeCh := make(chan WebSocketFrame)
	closeCh := make(chan struct{})
	closeDone := make(chan struct{})

	wsConn := WebSocketConnection{
		conn:      conn,
		readCh:    readCh,
		writeCh:   writeCh,
		closeCh:   closeCh,
		closeDone: closeDone,
	}
	go s.readWebSocketData(&wsConn)
	go s.writeWebSocketData(&wsConn)

	// Wait for the close signal from either the read or write goroutines
	select {
	case <-closeDone:
		s.config.Logger.Println("WebSocket connection closed")
	}
}

func (s *WebSocketServer) closeConn(reason string, status uint16, wsConn *WebSocketConnection) error {

	closePayload := make([]byte, 2+len([]byte(reason)))
	binary.BigEndian.PutUint16(closePayload, status)
	copy(closePayload[2:], reason)

	err := s.writeWebSocketFrame(wsConn.conn, &WebSocketFrame{
		opcode:  OpClose,
		fin:     true,
		payload: closePayload,
	})

	if err != nil {
		return err
	}

	err = wsConn.conn.Close()
	if err != nil {
		return err
	}

	close(wsConn.closeDone)
	return nil
}

func (s *WebSocketServer) readWebSocketData(wsConn *WebSocketConnection) {
	conn := wsConn.conn
	closeCh := wsConn.closeCh

	writeCh := wsConn.writeCh
	finalPayload := make([]byte, 0, defaultPayloadInitialBufferSize)

	var overWriteOpcode byte
	prevWasFinBinOrText := true
	nextCantBeBinOrText := false

	for {
		frame, err := s.readWebSocketFrame(conn)

		if err != nil {
			if err.Error() == "RSV must be 0" {
				s.closeConn("Not zero RSV not expected", 1002, wsConn)
				return
			}
		}

		fin := frame.fin
		opcode := frame.opcode
		payload := frame.payload

		if prevWasFinBinOrText && opcode == OpContinuation {
			s.closeConn("Received unexpected continuation", 1002, wsConn)
			return
		}
		prevWasFinBinOrText = fin && (opcode == OpBinary || opcode == OpText || opcode == OpContinuation)
		if nextCantBeBinOrText && (opcode == OpBinary || opcode == OpText) {
			s.closeConn("Unexpected bin or text frame", 1002, wsConn)
		}
		if opcode == OpContinuation {
			opcode = overWriteOpcode
			nextCantBeBinOrText = true
		}
		if err != nil {
			close(closeCh)
			return
		}

		if opcode == OpPing { // need to respond to ping immediately
			if len(payload) > 125 {
				err = s.closeConn("Ping payload can not be greater than 125 bytes: Closing connection", 1002, wsConn)
				if err != nil {
					s.config.Logger.Fatal(err.Error())
				}
				return
			} else if !fin {
				err = s.closeConn("Ping payload set FIN=0: Closing connection", 1002, wsConn)
				return
			}

			err := s.writeWebSocketFrame(conn, &WebSocketFrame{
				opcode:  OpPong,
				payload: payload,
				fin:     true,
			})

			if err != nil {
				s.config.Logger.Println("Error sending pong frame:", err)
			}

			continue
		} else if opcode == OpClose { // we received close, close immediately
			var returnStatus uint16
			if len(payload) == 1 || len(payload) > 125 {
				returnStatus = 1002
			} else {
				if len(payload) > 0 {
					code := binary.BigEndian.Uint16(payload[:2])
					if !webSocketCodeIsValid(code) {
						returnStatus = 1002
					} else {
						returnStatus = 1000
					}
				} else {
					returnStatus = 1000
				}
			}
			s.closeConn("Connection closed by the server", returnStatus, wsConn)
			return
		} else if opcode == OpPong { // acknowledge pong immediately
			s.config.Logger.Println("Received pong frame with payload:", payload)
			continue
		}

		finalPayload = append(finalPayload, payload...)
		if !fin {
			if opcode == OpBinary || opcode == OpText {
				overWriteOpcode = opcode
				nextCantBeBinOrText = true
			}
			continue

		}
		switch opcode {
		case OpText:
			if s.config.DisableUtf8Validation == false && !utf8.Valid(finalPayload) {
				s.closeConn("Uf8-payload is not valid", 1002, wsConn)
				return
			}

			outputMessage := s.useMessageHandler(finalPayload, OpText)
			if outputMessage != nil {
				writeCh <- WebSocketFrame{
					fin:     true,
					opcode:  OpText,
					payload: outputMessage,
				}
			}
			finalPayload = make([]byte, 0, defaultPayloadInitialBufferSize)
		case OpBinary:
			outputMessage := s.useMessageHandler(finalPayload, OpBinary)
			if outputMessage != nil {
				writeCh <- WebSocketFrame{
					fin:     true,
					opcode:  OpBinary,
					payload: outputMessage,
				}
			}
			finalPayload = make([]byte, 0, defaultPayloadInitialBufferSize)
		default:
			s.closeConn("Unknown opcode closing connection", 1002, wsConn)
			return
		}
	}
}

func (s *WebSocketServer) useMessageHandler(message []byte, messageType OpCode) []byte {
	if messageType == OpText {
		if s.config.OnTextMessageHandler != nil {
			return s.config.OnTextMessageHandler(message)
		} else if s.config.OnMessageHandler != nil {
			return s.config.OnMessageHandler(message)
		} else {
			return nil
		}
	} else if messageType == OpBinary {
		if s.config.OnBinaryMessageHandler != nil {
			return s.config.OnBinaryMessageHandler(message)
		} else if s.config.OnMessageHandler != nil {
			return s.config.OnMessageHandler(message)
		} else {
			return nil
		}
	}
	return nil
}
func (s *WebSocketServer) writeWebSocketData(wsConn *WebSocketConnection) {
	conn := wsConn.conn
	writeCh := wsConn.writeCh
	closeCh := wsConn.closeCh
	closeDone := wsConn.closeDone

	for {
		select {
		case frame := <-writeCh:
			err := s.writeWebSocketFrame(conn, &frame)
			if err != nil {
				close(closeCh)
				return
			}
		case <-closeCh:
			close(closeDone)
			return
		}
	}
}
