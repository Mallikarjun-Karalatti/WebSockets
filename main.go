package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ---------- WebSocket Constants (RFC 6455) ----------

const (
	WebSocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

	OpContinuation = 0x0
	OpText         = 0x1
	OpBinary       = 0x2
	OpClose        = 0x8
	OpPing         = 0x9
	OpPong         = 0xA

	CloseNormalClosure = 1000

	DefaultPort             = "8084"
	DefaultHeartbeatInterval = 20 * time.Second
	DefaultHeartbeatTimeout  = 10 * time.Second
	MaxFramePayload          = 10 * 1024 * 1024 // 10 MB maximum frame size
	MaxHistoryPerRoom        = 20
)

// ---------- Frame Framing (RFC 6455) ----------

// Frame represents a single WebSocket frame.
type Frame struct {
	Opcode  int
	Payload []byte
}

// ReadFrame reads a complete WebSocket frame (handling fragmented frames if necessary).
// Browser-to-server frames are masked according to RFC 6455 §5.3.
func ReadFrame(r io.Reader) (*Frame, error) {
	var messageBuf bytes.Buffer
	messageOpcode := -1

	for {
		header := make([]byte, 2)
		if _, err := io.ReadFull(r, header); err != nil {
			return nil, err
		}

		b0 := header[0]
		b1 := header[1]

		fin := (b0 & 0x80) != 0
		opcode := int(b0 & 0x0F)
		masked := (b1 & 0x80) != 0
		payloadLen := int64(b1 & 0x7F)

		switch payloadLen {
		case 126:
			lenBuf := make([]byte, 2)
			if _, err := io.ReadFull(r, lenBuf); err != nil {
				return nil, err
			}
			payloadLen = int64(binary.BigEndian.Uint16(lenBuf))
		case 127:
			lenBuf := make([]byte, 8)
			if _, err := io.ReadFull(r, lenBuf); err != nil {
				return nil, err
			}
			payloadLen = int64(binary.BigEndian.Uint64(lenBuf))
		}

		if payloadLen > MaxFramePayload {
			return nil, fmt.Errorf("frame payload length %d exceeds max %d", payloadLen, MaxFramePayload)
		}

		var maskKey []byte
		if masked {
			maskKey = make([]byte, 4)
			if _, err := io.ReadFull(r, maskKey); err != nil {
				return nil, err
			}
		}

		data := make([]byte, payloadLen)
		if _, err := io.ReadFull(r, data); err != nil {
			return nil, err
		}

		if masked && maskKey != nil {
			for i := 0; i < len(data); i++ {
				data[i] ^= maskKey[i%4]
			}
		}

		// Control frames (Opcode >= 0x8) are never fragmented and must have payload <= 125 bytes
		if opcode >= 0x8 {
			return &Frame{Opcode: opcode, Payload: data}, nil
		}

		if messageOpcode == -1 {
			messageOpcode = opcode
		}
		messageBuf.Write(data)

		if fin {
			return &Frame{Opcode: messageOpcode, Payload: messageBuf.Bytes()}, nil
		}
	}
}

// WriteFrame encodes and transmits a frame to the wire.
// Server-to-client frames MUST NOT be masked according to RFC 6455 §5.1.
func WriteFrame(w io.Writer, opcode int, payload []byte) error {
	var header bytes.Buffer

	// Byte 0: FIN (1 bit) + RSV (3 bits = 0) + Opcode (4 bits)
	header.WriteByte(byte(0x80 | (opcode & 0x0F)))

	// Byte 1+: MASK (0 for server) + Payload length encoding
	n := len(payload)
	if n < 126 {
		header.WriteByte(byte(n))
	} else if n <= 0xFFFF {
		header.WriteByte(126)
		lenBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(lenBuf, uint16(n))
		header.Write(lenBuf)
	} else {
		header.WriteByte(127)
		lenBuf := make([]byte, 8)
		binary.BigEndian.PutUint64(lenBuf, uint64(n))
		header.Write(lenBuf)
	}

	if _, err := w.Write(header.Bytes()); err != nil {
		return err
	}
	if n > 0 {
		if _, err := w.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

// ComputeAcceptKey computes Base64(SHA-1(key + GUID)) required by RFC 6455 §4.2.2.
func ComputeAcceptKey(challengeKey string) string {
	sum := sha1.Sum([]byte(strings.TrimSpace(challengeKey) + WebSocketGUID))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// ---------- Domain Client & Server ----------

// Client represents one connected WebSocket session.
type Client struct {
	User     string
	Room     string
	Conn     net.Conn
	mu       sync.Mutex // synchronizes writes to Conn
	closed   atomic.Bool
	lastPong atomic.Int64
}

// SendText sends a UTF-8 text frame to this client.
func (c *Client) SendText(text string) error {
	return c.SendRaw(OpText, []byte(text))
}

// SendRaw sends an arbitrary opcode frame to this client.
func (c *Client) SendRaw(opcode int, payload []byte) error {
	if c.closed.Load() {
		return errors.New("client connection closed")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return WriteFrame(c.Conn, opcode, payload)
}

// Close gracefully terminates the WebSocket connection with an RFC 6455 Close frame.
func (c *Client) Close(code int, reason string) error {
	if c.closed.Swap(true) {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	// Build Close payload: 2-byte code + reason string
	payload := make([]byte, 2+len(reason))
	binary.BigEndian.PutUint16(payload[:2], uint16(code))
	copy(payload[2:], reason)
	_ = WriteFrame(c.Conn, OpClose, payload)
	return c.Conn.Close()
}

func (c *Client) String() string {
	return fmt.Sprintf("%s@%s", c.User, c.Room)
}

// ChatServer manages rooms, message broadcasting, history, and heartbeats.
type ChatServer struct {
	mu                sync.RWMutex
	rooms             map[string]map[*Client]struct{}
	history           map[string][]map[string]any
	heartbeatInterval time.Duration
	heartbeatTimeout  time.Duration
	stopCh            chan struct{}
}

// NewChatServer constructs a new ChatServer instance.
func NewChatServer() *ChatServer {
	s := &ChatServer{
		rooms:             make(map[string]map[*Client]struct{}),
		history:           make(map[string][]map[string]any),
		heartbeatInterval: DefaultHeartbeatInterval,
		heartbeatTimeout:  DefaultHeartbeatTimeout,
		stopCh:            make(chan struct{}),
	}
	go s.heartbeatLoop()
	return s
}

// Close terminates the server and background goroutines.
func (s *ChatServer) Close() {
	select {
	case <-s.stopCh:
		return
	default:
		close(s.stopCh)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for _, clients := range s.rooms {
		for c := range clients {
			_ = c.Close(CloseNormalClosure, "server shutdown")
		}
	}
	s.rooms = make(map[string]map[*Client]struct{})
}

// OnOpen handles a newly upgraded WebSocket client connection.
func (s *ChatServer) OnOpen(c *Client) {
	s.mu.Lock()
	clients, ok := s.rooms[c.Room]
	if !ok {
		clients = make(map[*Client]struct{})
		s.rooms[c.Room] = clients
	}
	clients[c] = struct{}{}

	// Snapshot online users and room history under lock
	online := s.getOnlineUsersUnderLock(c.Room)
	roomHistory := make([]map[string]any, len(s.history[c.Room]))
	copy(roomHistory, s.history[c.Room])
	s.mu.Unlock()

	// Broadcast joined system notification to everyone in the room
	systemMsg := map[string]any{
		"type":   "system",
		"text":   fmt.Sprintf("%s joined", c.User),
		"online": online,
	}
	s.Broadcast(c.Room, systemMsg, nil)

	// Stretch Goal: Replay recent room history to newcomer
	for _, histMsg := range roomHistory {
		data, err := json.Marshal(histMsg)
		if err == nil {
			_ = c.SendText(string(data))
		}
	}
}

// OnMessage routes client messages:
// - "message" -> broadcast to all (including sender as delivery receipt)
// - "typing"  -> broadcast to all EXCEPT sender
// - other     -> return {"type":"error","text":"unknown message type"} to sender
func (s *ChatServer) OnMessage(c *Client, rawText string) {
	var payload map[string]any
	if err := json.Unmarshal([]byte(rawText), &payload); err != nil {
		errResp, _ := json.Marshal(map[string]any{
			"type": "error",
			"text": "malformed JSON: " + err.Error(),
		})
		_ = c.SendText(string(errResp))
		return
	}

	msgType, _ := payload["type"].(string)

	switch msgType {
	case "message":
		textVal, _ := payload["text"].(string)
		if strings.TrimSpace(textVal) == "" {
			return // Blank messages are completely ignored
		}

		msg := map[string]any{
			"type": "message",
			"from": c.User,
			"text": textVal,
			"at":   time.Now().UnixMilli(),
		}

		// Record message in room history ring buffer
		s.mu.Lock()
		h := s.history[c.Room]
		if len(h) >= MaxHistoryPerRoom {
			h = h[1:]
		}
		s.history[c.Room] = append(h, msg)
		s.mu.Unlock()

		s.Broadcast(c.Room, msg, nil)

	case "typing":
		msg := map[string]any{
			"type": "typing",
			"from": c.User,
		}
		s.Broadcast(c.Room, msg, c)

	default:
		errResp, _ := json.Marshal(map[string]any{
			"type": "error",
			"text": "unknown message type",
		})
		_ = c.SendText(string(errResp))
	}
}

// OnClose handles client disconnects and notifies remaining participants.
func (s *ChatServer) OnClose(c *Client) {
	if c.closed.Swap(true) {
		return
	}
	_ = c.Conn.Close()

	s.mu.Lock()
	clients, ok := s.rooms[c.Room]
	if !ok {
		s.mu.Unlock()
		return
	}
	delete(clients, c)

	var remainingOnline []string
	if len(clients) == 0 {
		delete(s.rooms, c.Room)
		delete(s.history, c.Room)
		s.mu.Unlock()
		return
	}

	remainingOnline = s.getOnlineUsersUnderLock(c.Room)
	s.mu.Unlock()

	systemMsg := map[string]any{
		"type":   "system",
		"text":   fmt.Sprintf("%s left", c.User),
		"online": remainingOnline,
	}
	s.Broadcast(c.Room, systemMsg, nil)
}

// Broadcast sends a JSON-encoded message to all clients in the room except `except` (if non-nil).
func (s *ChatServer) Broadcast(room string, msg map[string]any, except *Client) {
	data, err := json.Marshal(msg)
	if err != nil {
		return
	}
	text := string(data)

	s.mu.RLock()
	clientsMap := s.rooms[room]
	recipients := make([]*Client, 0, len(clientsMap))
	for client := range clientsMap {
		if client != except {
			recipients = append(recipients, client)
		}
	}
	s.mu.RUnlock()

	for _, client := range recipients {
		if err := client.SendText(text); err != nil {
			log.Printf("[broadcast] could not reach %s (%v)", client, err)
		}
	}
}

func (s *ChatServer) getOnlineUsersUnderLock(room string) []string {
	clients := s.rooms[room]
	names := make([]string, 0, len(clients))
	for client := range clients {
		names = append(names, client.User)
	}
	sort.Strings(names)
	return names
}

// heartbeatLoop (Stretch Goal) periodically pings clients to detect dead sockets.
func (s *ChatServer) heartbeatLoop() {
	ticker := time.NewTicker(s.heartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.mu.RLock()
			var allClients []*Client
			for _, clients := range s.rooms {
				for c := range clients {
					allClients = append(allClients, c)
				}
			}
			s.mu.RUnlock()

			now := time.Now().UnixMilli()
			for _, c := range allClients {
				if c.closed.Load() {
					continue
				}
				// Verify if client missed previous heartbeats
				lastPong := c.lastPong.Load()
				if lastPong > 0 && (now-lastPong) > s.heartbeatTimeout.Milliseconds()*2+s.heartbeatInterval.Milliseconds() {
					log.Printf("[heartbeat] client %s timed out, terminating", c)
					go s.OnClose(c)
					continue
				}

				if err := c.SendRaw(OpPing, []byte("hb")); err != nil {
					go s.OnClose(c)
				}
			}
		}
	}
}

// ---------- HTTP & Upgrade Handlers ----------

func (s *ChatServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/":
		if r.Method != http.MethodGet {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(ChatHTML))

	case "/chat":
		s.handleChatUpgrade(w, r)

	default:
		http.Error(w, "Not found", http.StatusNotFound)
	}
}

func (s *ChatServer) handleChatUpgrade(w http.ResponseWriter, r *http.Request) {
	// 1. Plain HTTP request check: must have Upgrade: websocket
	upgradeHdr := strings.ToLower(r.Header.Get("Upgrade"))
	if !strings.Contains(upgradeHdr, "websocket") {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("This endpoint only speaks WebSocket (send Upgrade: websocket)"))
		return
	}

	// 2. Query parameter validation
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("Need ?order=...&user=..."))
		return
	}

	order := strings.TrimSpace(q.Get("order"))
	user := strings.TrimSpace(q.Get("user"))
	if order == "" || user == "" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("Need ?order=...&user=..."))
		return
	}

	// 3. Challenge key handshake validation
	secKey := r.Header.Get("Sec-WebSocket-Key")
	if strings.TrimSpace(secKey) == "" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("Bad handshake: missing Sec-WebSocket-Key"))
		return
	}

	acceptKey := ComputeAcceptKey(secKey)

	// 4. Hijack raw TCP socket
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Webserver does not support hijacking", http.StatusInternalServerError)
		return
	}

	conn, buf, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 5. Send HTTP 101 Switching Protocols response
	resp := fmt.Sprintf("HTTP/1.1 101 Switching Protocols\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Accept: %s\r\n\r\n", acceptKey)

	if _, err := buf.WriteString(resp); err != nil {
		_ = conn.Close()
		return
	}
	if err := buf.Flush(); err != nil {
		_ = conn.Close()
		return
	}

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
	}

	client := &Client{
		User: user,
		Room: order,
		Conn: conn,
	}
	client.lastPong.Store(time.Now().UnixMilli())

	log.Printf("+ %s connected", client)
	s.OnOpen(client)

	// 6. Frame processing loop until disconnect or close frame
	go func() {
		defer func() {
			log.Printf("- %s disconnected", client)
			s.OnClose(client)
		}()

		for {
			frame, err := ReadFrame(buf)
			if err != nil {
				return // TCP disconnected or error
			}

			switch frame.Opcode {
			case OpText:
				s.OnMessage(client, string(frame.Payload))

			case OpPing:
				_ = client.SendRaw(OpPong, frame.Payload)

			case OpPong:
				client.lastPong.Store(time.Now().UnixMilli())

			case OpClose:
				_ = client.SendRaw(OpClose, frame.Payload)
				return

			default:
				// Binary or unrecognized opcodes: ignored
			}
		}
	}()
}

// ---------- Embedded Chat Client UI ----------

const ChatHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>QuickBite Rider Chat</title>
  <style>
    * { box-sizing: border-box; }
    body {
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #12002b;
      color: #fff;
      max-width: 600px;
      margin: 24px auto;
      padding: 0 16px;
    }
    h1 {
      background: linear-gradient(90deg, #00e5ff, #d500f9);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      margin-bottom: 8px;
    }
    .badge {
      display: inline-block;
      padding: 3px 10px;
      border-radius: 999px;
      background: #555;
      font-size: 12px;
      font-weight: 600;
      vertical-align: middle;
      transition: background 0.3s;
    }
    .badge.on { background: #00e676; color: #002; }
    .badge.warn { background: #ff9100; color: #002; }
    .controls {
      display: flex;
      gap: 8px;
      align-items: center;
      margin-bottom: 12px;
      flex-wrap: wrap;
    }
    input, button {
      font: inherit;
      border-radius: 10px;
      border: 0;
      padding: 10px 14px;
      outline: none;
    }
    input { background: #2a1050; color: #fff; }
    input:focus { box-shadow: 0 0 0 2px #00e5ff; }
    button {
      background: #ff3d00;
      color: #fff;
      font-weight: 700;
      cursor: pointer;
      transition: opacity 0.2s;
    }
    button:hover { opacity: 0.9; }
    #log {
      height: 380px;
      overflow-y: auto;
      background: #1c0840;
      border-radius: 14px;
      padding: 14px;
      margin: 12px 0;
      display: flex;
      flex-direction: column;
      gap: 8px;
    }
    .msg {
      padding: 9px 14px;
      border-radius: 14px;
      max-width: 82%;
      width: fit-content;
      word-break: break-word;
      font-size: 14px;
      line-height: 1.4;
    }
    .me {
      background: #00c853;
      align-self: flex-end;
      border-bottom-right-radius: 2px;
    }
    .them {
      background: #2979ff;
      align-self: flex-start;
      border-bottom-left-radius: 2px;
    }
    .sys {
      color: #ffea00;
      font-size: 12px;
      text-align: center;
      align-self: center;
      padding: 2px 8px;
    }
    .err {
      color: #ff5252;
      font-size: 13px;
      text-align: center;
      align-self: center;
    }
    #typing {
      height: 20px;
      font-size: 13px;
      color: #18ffff;
      font-style: italic;
    }
    #sendForm {
      display: flex;
      gap: 8px;
    }
    #sendForm input { flex: 1; }
  </style>
</head>
<body>
  <h1>Rider ⇄ Customer Chat</h1>
  <div class="controls">
    <input id="order" value="ord_42" placeholder="order id" style="width: 130px;">
    <input id="user" placeholder="your name" style="width: 180px;">
    <button id="go">Join Room</button>
    <span id="state" class="badge">offline</span>
  </div>

  <div id="log"></div>
  <div id="typing"></div>

  <form id="sendForm">
    <input id="text" placeholder="Type a message..." autocomplete="off">
    <button type="submit">Send</button>
  </form>

  <script>
    let ws = null;
    let me = '';
    let typingTimer = null;
    let reconnectDelay = 1000;
    let shouldReconnect = false;

    const $ = id => document.getElementById(id);
    const log = $('log');

    function appendBubble(cls, text) {
      const d = document.createElement('div');
      d.className = 'msg ' + cls;
      d.textContent = text;
      log.appendChild(d);
      log.scrollTop = log.scrollHeight;
    }

    $('user').value = ['Ravi (rider)', 'Asha (customer)'][Math.floor(Math.random() * 2)];

    function connect() {
      me = $('user').value.trim();
      const order = $('order').value.trim();
      if (!me || !order) return;

      shouldReconnect = true;
      $('state').textContent = 'connecting...';
      $('state').className = 'badge warn';

      const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
      ws = new WebSocket(proto + '//' + location.host + '/chat?order=' + encodeURIComponent(order) + '&user=' + encodeURIComponent(me));

      ws.onopen = () => {
        $('state').textContent = 'connected';
        $('state').className = 'badge on';
        reconnectDelay = 1000; // Reset exponential backoff
      };

      ws.onclose = () => {
        $('state').textContent = 'offline';
        $('state').className = 'badge';
        if (shouldReconnect) {
          appendBubble('sys', 'Connection lost. Reconnecting in ' + (reconnectDelay / 1000) + 's...');
          setTimeout(() => {
            if (shouldReconnect) connect();
          }, reconnectDelay);
          reconnectDelay = Math.min(reconnectDelay * 2, 30000); // Max 30s backoff
        }
      };

      ws.onerror = () => {
        ws.close();
      };

      ws.onmessage = e => {
        try {
          const m = JSON.parse(e.data);
          if (m.type === 'message') {
            $('typing').textContent = '';
            const prefix = (m.from === me) ? '' : (m.from + ': ');
            appendBubble(m.from === me ? 'me' : 'them', prefix + m.text);
          } else if (m.type === 'system') {
            const list = Array.isArray(m.online) ? m.online.join(', ') : '';
            appendBubble('sys', m.text + ' · online: [' + list + ']');
          } else if (m.type === 'typing') {
            $('typing').textContent = m.from + ' is typing...';
            clearTimeout(typingTimer);
            typingTimer = setTimeout(() => { $('typing').textContent = ''; }, 1500);
          } else if (m.type === 'error') {
            appendBubble('err', m.text);
          }
        } catch (err) {
          console.error('Failed to parse frame message', err);
        }
      };
    }

    $('go').onclick = () => {
      if (ws) {
        shouldReconnect = false;
        ws.close();
      }
      reconnectDelay = 1000;
      connect();
    };

    $('text').oninput = () => {
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'typing' }));
      }
    };

    $('sendForm').onsubmit = e => {
      e.preventDefault();
      const input = $('text');
      const val = input.value.trim();
      if (ws && ws.readyState === WebSocket.OPEN && val) {
        ws.send(JSON.stringify({ type: 'message', text: input.value }));
        input.value = '';
      }
    };
  </script>
</body>
</html>`

// ---------- Main CLI Runner ----------

func main() {
	port := flag.String("port", DefaultPort, "Port to listen on or connect to")
	clientMode := flag.Bool("client", false, "Run in interactive terminal client mode")
	orderFlag := flag.String("order", "ord_42", "Order ID (room) for client mode")
	userFlag := flag.String("user", "", "User name for client mode (defaults to random)")
	flag.Parse()

	if envPort := os.Getenv("PORT"); envPort != "" {
		*port = envPort
	}

	if *clientMode {
		user := *userFlag
		if user == "" {
			user = fmt.Sprintf("terminal-%d", time.Now().UnixNano()%100)
		}
		runClient(*port, *orderFlag, user)
		return
	}

	server := NewChatServer()
	defer server.Close()

	httpServer := &http.Server{
		Addr:    ":" + *port,
		Handler: server,
	}

	go func() {
		log.Printf("Chat server listening on http://localhost:%s (open in two tabs)", *port)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	log.Println("Shutting down chat server gracefully...")
	server.Close()
	_ = httpServer.Close()
}

// runClient runs an interactive terminal chat client.
func runClient(port, order, user string) {
	addr := "localhost:" + port
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		log.Fatalf("Failed to connect to %s: %v (make sure the server is running)", addr, err)
	}
	defer conn.Close()

	keyBytes := make([]byte, 16)
	_, _ = rand.Read(keyBytes)
	challengeKey := base64.StdEncoding.EncodeToString(keyBytes)

	req := fmt.Sprintf("GET /chat?order=%s&user=%s HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Key: %s\r\n"+
		"Sec-WebSocket-Version: 13\r\n\r\n",
		url.QueryEscape(order), url.QueryEscape(user), addr, challengeKey)

	if _, err := conn.Write([]byte(req)); err != nil {
		log.Fatalf("Failed to send handshake: %v", err)
	}

	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil || !strings.Contains(statusLine, "101") {
		log.Fatalf("Handshake rejected by server: %s (err: %v)", statusLine, err)
	}

	for {
		line, err := reader.ReadString('\n')
		if err != nil || strings.TrimRight(line, "\r\n") == "" {
			break
		}
	}

	fmt.Printf("[open] Handshake successful — joined room '%s' as '%s'\n", order, user)
	fmt.Println("Type a message and press Enter to send. Type /quit to leave.")

	stopCh := make(chan struct{})

	// Receiver loop
	go func() {
		for {
			frame, err := ReadFrame(reader)
			if err != nil {
				fmt.Println("\n[disconnected from server]")
				close(stopCh)
				return
			}
			switch frame.Opcode {
			case OpText:
				fmt.Printf("<< %s\n", string(frame.Payload))
			case OpClose:
				fmt.Println("\n[server closed connection]")
				close(stopCh)
				return
			case OpPing:
				_ = sendMaskedClientFrame(conn, OpPong, frame.Payload)
			}
		}
	}()

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		select {
		case <-stopCh:
			return
		default:
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.EqualFold(line, "/quit") {
			_ = sendMaskedClientFrame(conn, OpClose, []byte{0x03, 0xE8, 'b', 'y', 'e'})
			fmt.Println("[closed] Normal closure")
			return
		}

		msgJSON, _ := json.Marshal(map[string]any{
			"type": "message",
			"text": line,
		})
		if err := sendMaskedClientFrame(conn, OpText, msgJSON); err != nil {
			fmt.Printf("[error sending frame: %v]\n", err)
			return
		}
	}
}

func sendMaskedClientFrame(w io.Writer, opcode int, payload []byte) error {
	var buf bytes.Buffer
	buf.WriteByte(byte(0x80 | (opcode & 0x0F)))
	n := len(payload)
	maskKey := make([]byte, 4)
	_, _ = rand.Read(maskKey)

	if n < 126 {
		buf.WriteByte(byte(0x80 | n))
	} else if n <= 0xFFFF {
		buf.WriteByte(byte(0x80 | 126))
		lenBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(lenBuf, uint16(n))
		buf.Write(lenBuf)
	} else {
		buf.WriteByte(byte(0x80 | 127))
		lenBuf := make([]byte, 8)
		binary.BigEndian.PutUint64(lenBuf, uint64(n))
		buf.Write(lenBuf)
	}

	buf.Write(maskKey)
	masked := make([]byte, n)
	copy(masked, payload)
	for i := 0; i < n; i++ {
		masked[i] ^= maskKey[i%4]
	}
	buf.Write(masked)

	_, err := w.Write(buf.Bytes())
	return err
}
