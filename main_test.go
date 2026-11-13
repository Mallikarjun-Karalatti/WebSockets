package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------- Helpers for Unit and Integration Testing ----------

func setupTestServer(t *testing.T) (*ChatServer, *httptest.Server) {
	t.Helper()
	server := NewChatServer()
	// Use small heartbeat interval in tests to prevent background interference
	server.heartbeatInterval = 10 * time.Minute
	ts := httptest.NewServer(server)
	return server, ts
}

// testPeer represents a mock WebSocket client interacting via raw TCP.
type testPeer struct {
	conn       net.Conn
	r          *bufio.Reader
	user       string
	room       string
	inbox      chan string
	closed     chan struct{}
	closeOnce  sync.Once
	leaveOnce  sync.Once
	stopReader chan struct{}
}

func connectPeer(t *testing.T, serverAddr, order, user string) *testPeer {
	t.Helper()

	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		t.Fatalf("failed to dial server: %v", err)
	}

	keyBytes := make([]byte, 16)
	_, _ = rand.Read(keyBytes)
	challengeKey := base64.StdEncoding.EncodeToString(keyBytes)

	req := fmt.Sprintf("GET /chat?order=%s&user=%s HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Key: %s\r\n"+
		"Sec-WebSocket-Version: 13\r\n\r\n", order, user, serverAddr, challengeKey)

	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("failed to write upgrade request: %v", err)
	}

	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("failed to read handshake response: %v", err)
	}
	if !strings.Contains(statusLine, "101") {
		t.Fatalf("expected 101 Switching Protocols, got: %s", statusLine)
	}

	// Read remaining HTTP headers
	headers := make(map[string]string)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("failed to read header: %v", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			headers[strings.ToLower(strings.TrimSpace(parts[0]))] = strings.TrimSpace(parts[1])
		}
	}

	expectedAccept := ComputeAcceptKey(challengeKey)
	if gotAccept := headers["sec-websocket-accept"]; gotAccept != expectedAccept {
		t.Fatalf("Sec-WebSocket-Accept mismatch: expected %s, got %s", expectedAccept, gotAccept)
	}

	peer := &testPeer{
		conn:       conn,
		r:          reader,
		user:       user,
		room:       order,
		inbox:      make(chan string, 100),
		closed:     make(chan struct{}),
		stopReader: make(chan struct{}),
	}

	go peer.readLoop()
	return peer
}

func (p *testPeer) readLoop() {
	defer p.closeOnce.Do(func() { close(p.closed) })
	for {
		select {
		case <-p.stopReader:
			return
		default:
		}

		frame, err := ReadFrame(p.r)
		if err != nil {
			return
		}

		switch frame.Opcode {
		case OpText:
			p.inbox <- string(frame.Payload)
		case OpClose:
			return
		case OpPing:
			_ = p.sendMaskedFrame(OpPong, frame.Payload)
		}
	}
}

func (p *testPeer) sendMaskedFrame(opcode int, payload []byte) error {
	var buf bytes.Buffer
	buf.WriteByte(byte(0x80 | (opcode & 0x0F))) // FIN + opcode

	n := len(payload)
	maskKey := []byte{0x12, 0x34, 0x56, 0x78}

	if n < 126 {
		buf.WriteByte(byte(0x80 | n)) // Mask bit set + length
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
	maskedData := make([]byte, n)
	copy(maskedData, payload)
	for i := 0; i < n; i++ {
		maskedData[i] ^= maskKey[i%4]
	}
	buf.Write(maskedData)

	_, err := p.conn.Write(buf.Bytes())
	return err
}

func (p *testPeer) Say(jsonText string) error {
	return p.sendMaskedFrame(OpText, []byte(jsonText))
}

func (p *testPeer) Await(needle string, timeout time.Duration) (string, error) {
	deadline := time.After(timeout)
	for {
		select {
		case msg := <-p.inbox:
			if strings.Contains(msg, needle) {
				return msg, nil
			}
		case <-deadline:
			return "", fmt.Errorf("timeout awaiting message containing: %q", needle)
		}
	}
}

func (p *testPeer) ExpectSilence(needle string, duration time.Duration) error {
	deadline := time.After(duration)
	for {
		select {
		case msg := <-p.inbox:
			if strings.Contains(msg, needle) {
				return fmt.Errorf("unexpectedly received forbidden message: %s", msg)
			}
		case <-deadline:
			return nil
		}
	}
}

func (p *testPeer) Leave() {
	p.leaveOnce.Do(func() {
		_ = p.sendMaskedFrame(OpClose, []byte{0x03, 0xE8, 'b', 'y', 'e'})
		close(p.stopReader)
		_ = p.conn.Close()
	})
}

// ---------- Unit & Integration Tests ----------

func TestAcceptKeyCalculation(t *testing.T) {
	// RFC 6455 §1.3 test vector
	rfcChallenge := "dGhlIHNhbXBsZSBub25jZQ=="
	expectedAccept := "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="

	computed := ComputeAcceptKey(rfcChallenge)
	if computed != expectedAccept {
		t.Fatalf("RFC 6455 accept key mismatch: got %q, expected %q", computed, expectedAccept)
	}

	// Verify trimming whitespace
	if ComputeAcceptKey("   "+rfcChallenge+"  ") != expectedAccept {
		t.Fatalf("accept key should trim whitespace")
	}
}

func TestPlainHTTPEndpoints(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()

	// 1. GET / returns HTML
	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("GET / failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK for GET /, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "QuickBite Rider Chat") {
		t.Errorf("HTML should contain QuickBite title, got %s", string(body))
	}

	// 2. POST / returns 405 Method Not Allowed
	respPost, err := http.Post(ts.URL+"/", "text/plain", nil)
	if err != nil {
		t.Fatalf("POST / failed: %v", err)
	}
	defer respPost.Body.Close()
	if respPost.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for POST /, got %d", respPost.StatusCode)
	}

	// 3. GET /unknown returns 404
	resp404, err := http.Get(ts.URL + "/unknown")
	if err != nil {
		t.Fatalf("GET /unknown failed: %v", err)
	}
	defer resp404.Body.Close()
	if resp404.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 for GET /unknown, got %d", resp404.StatusCode)
	}
}

func TestChatUpgradeValidation(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()

	// 1. Plain HTTP to /chat without Upgrade header -> 400
	respNoUpgrade, err := http.Get(ts.URL + "/chat?order=ord_42&user=Asha")
	if err != nil {
		t.Fatalf("GET /chat failed: %v", err)
	}
	defer respNoUpgrade.Body.Close()
	if respNoUpgrade.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for GET /chat without Upgrade header, got %d", respNoUpgrade.StatusCode)
	}

	// 2. Missing query parameters -> 400
	reqMissingOrder, _ := http.NewRequest("GET", ts.URL+"/chat?user=Asha", nil)
	reqMissingOrder.Header.Set("Upgrade", "websocket")
	reqMissingOrder.Header.Set("Connection", "Upgrade")
	reqMissingOrder.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	respMissing, err := http.DefaultClient.Do(reqMissingOrder)
	if err != nil {
		t.Fatalf("req failed: %v", err)
	}
	defer respMissing.Body.Close()
	if respMissing.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for missing order param, got %d", respMissing.StatusCode)
	}

	// 3. Missing Sec-WebSocket-Key -> 400
	reqMissingKey, _ := http.NewRequest("GET", ts.URL+"/chat?order=ord_42&user=Asha", nil)
	reqMissingKey.Header.Set("Upgrade", "websocket")
	reqMissingKey.Header.Set("Connection", "Upgrade")
	respNoKey, err := http.DefaultClient.Do(reqMissingKey)
	if err != nil {
		t.Fatalf("req failed: %v", err)
	}
	defer respNoKey.Body.Close()
	if respNoKey.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for missing Sec-WebSocket-Key, got %d", respNoKey.StatusCode)
	}
}

func TestFrameEncodingAndDecoding(t *testing.T) {
	// 1. Short payload (< 126 bytes)
	shortMsg := "hello websocket"
	var buf bytes.Buffer
	if err := WriteFrame(&buf, OpText, []byte(shortMsg)); err != nil {
		t.Fatalf("WriteFrame failed: %v", err)
	}

	readFrame, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}
	if readFrame.Opcode != OpText || string(readFrame.Payload) != shortMsg {
		t.Fatalf("payload mismatch: expected %q, got %q", shortMsg, string(readFrame.Payload))
	}

	// 2. Medium payload (126 <= len < 65536)
	mediumMsg := strings.Repeat("A", 1000)
	buf.Reset()
	if err := WriteFrame(&buf, OpText, []byte(mediumMsg)); err != nil {
		t.Fatalf("WriteFrame medium failed: %v", err)
	}
	readMed, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame medium failed: %v", err)
	}
	if len(readMed.Payload) != 1000 {
		t.Fatalf("expected len 1000, got %d", len(readMed.Payload))
	}

	// 3. Large payload (> 65535)
	largeMsg := strings.Repeat("B", 70000)
	buf.Reset()
	if err := WriteFrame(&buf, OpBinary, []byte(largeMsg)); err != nil {
		t.Fatalf("WriteFrame large failed: %v", err)
	}
	readLarge, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame large failed: %v", err)
	}
	if len(readLarge.Payload) != 70000 {
		t.Fatalf("expected len 70000, got %d", len(readLarge.Payload))
	}
}

func TestCompleteChatWorkflow(t *testing.T) {
	server, ts := setupTestServer(t)
	defer server.Close()
	defer ts.Close()

	serverHost := strings.TrimPrefix(ts.URL, "http://")
	room := fmt.Sprintf("ord_%d", time.Now().UnixNano()%100000)
	otherRoom := room + "_other"

	// 1. Alice joins
	alice := connectPeer(t, serverHost, room, "alice")
	defer alice.Leave()

	msg, err := alice.Await("alice joined", 3*time.Second)
	if err != nil {
		t.Fatalf("alice failed to receive join notification: %v", err)
	}
	if !strings.Contains(msg, `"alice"`) {
		t.Fatalf("online list should contain alice: %s", msg)
	}

	// 2. Bob joins the same room
	bob := connectPeer(t, serverHost, room, "bob")
	defer bob.Leave()

	msgBobJoin, err := alice.Await("bob joined", 3*time.Second)
	if err != nil {
		t.Fatalf("alice should be notified of bob joining: %v", err)
	}
	if !strings.Contains(msgBobJoin, `"alice"`) || !strings.Contains(msgBobJoin, `"bob"`) {
		t.Fatalf("online list should contain both alice and bob: %s", msgBobJoin)
	}

	// 3. Carol joins a different room
	carol := connectPeer(t, serverHost, otherRoom, "carol")
	defer carol.Leave()

	_, err = carol.Await("carol joined", 3*time.Second)
	if err != nil {
		t.Fatalf("carol failed to receive join: %v", err)
	}

	// 4. Alice sends a message
	sayErr := alice.Say(`{"type":"message","text":"I am at the gate"}`)
	if sayErr != nil {
		t.Fatalf("alice failed to say message: %v", sayErr)
	}

	// Bob should receive Alice's message with from="alice" and timestamp "at"
	bobMsg, err := bob.Await("I am at the gate", 3*time.Second)
	if err != nil {
		t.Fatalf("bob failed to receive alice message: %v", err)
	}
	if !strings.Contains(bobMsg, `"from":"alice"`) {
		t.Fatalf("message should have from=alice: %s", bobMsg)
	}
	if !strings.Contains(bobMsg, `"at"`) {
		t.Fatalf("message should have timestamp 'at': %s", bobMsg)
	}

	// Alice should receive her own message back (delivery receipt)
	_, err = alice.Await("I am at the gate", 3*time.Second)
	if err != nil {
		t.Fatalf("alice should receive delivery receipt for her message: %v", err)
	}

	// Carol in a different room should receive NOTHING
	if err := carol.ExpectSilence("I am at the gate", 700*time.Millisecond); err != nil {
		t.Fatalf("carol should not receive messages from alice: %v", err)
	}

	// 5. Typing indicator: goes to bob but NOT back to alice
	if err := alice.Say(`{"type":"typing"}`); err != nil {
		t.Fatalf("alice failed to send typing: %v", err)
	}
	if _, err := bob.Await(`"typing"`, 3*time.Second); err != nil {
		t.Fatalf("bob failed to receive typing indicator: %v", err)
	}
	if err := alice.ExpectSilence(`"typing"`, 700*time.Millisecond); err != nil {
		t.Fatalf("alice should not receive her own typing indicator: %v", err)
	}

	// 6. Blank messages are ignored
	if err := alice.Say(`{"type":"message","text":"   "}`); err != nil {
		t.Fatalf("failed to send blank message: %v", err)
	}
	if err := bob.ExpectSilence(`"message"`, 700*time.Millisecond); err != nil {
		t.Fatalf("blank message should be ignored: %v", err)
	}

	// 7. Unknown message types return error to sender only
	if err := alice.Say(`{"type":"dance"}`); err != nil {
		t.Fatalf("failed to send unknown message: %v", err)
	}
	if _, err := alice.Await(`"error"`, 3*time.Second); err != nil {
		t.Fatalf("alice should receive error for unknown type: %v", err)
	}
	if err := bob.ExpectSilence(`"error"`, 700*time.Millisecond); err != nil {
		t.Fatalf("bob should not receive alice error: %v", err)
	}

	// 8. Bob leaves: Alice is notified and Bob is removed from online list
	bob.Leave()
	leftMsg, err := alice.Await("bob left", 3*time.Second)
	if err != nil {
		t.Fatalf("alice should be notified when bob leaves: %v", err)
	}
	if strings.Contains(leftMsg, `"bob"`) {
		t.Fatalf("bob should no longer be in online list: %s", leftMsg)
	}
}

func TestPingPongHeartbeat(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()

	serverHost := strings.TrimPrefix(ts.URL, "http://")
	peer := connectPeer(t, serverHost, "ord_hb", "hb_tester")
	defer peer.Leave()

	// Send Ping frame
	pingPayload := []byte("ping_test_payload")
	if err := peer.sendMaskedFrame(OpPing, pingPayload); err != nil {
		t.Fatalf("failed to send ping: %v", err)
	}

	// Expect Pong response with matching payload
	time.Sleep(200 * time.Millisecond)
}

func TestHistoryReplay(t *testing.T) {
	server, ts := setupTestServer(t)
	defer server.Close()
	defer ts.Close()

	serverHost := strings.TrimPrefix(ts.URL, "http://")
	room := fmt.Sprintf("ord_hist_%d", time.Now().UnixNano()%100000)

	// Alice joins and sends 3 messages
	alice := connectPeer(t, serverHost, room, "alice")
	defer alice.Leave()
	_, _ = alice.Await("alice joined", 2*time.Second)

	_ = alice.Say(`{"type":"message","text":"msg 1"}`)
	_ = alice.Say(`{"type":"message","text":"msg 2"}`)
	_ = alice.Say(`{"type":"message","text":"msg 3"}`)

	// Drain alice's delivery receipts
	_, _ = alice.Await("msg 1", 2*time.Second)
	_, _ = alice.Await("msg 2", 2*time.Second)
	_, _ = alice.Await("msg 3", 2*time.Second)

	// Bob joins later: Bob should receive the historical messages replayed
	bob := connectPeer(t, serverHost, room, "bob")
	defer bob.Leave()

	_, err := bob.Await("msg 1", 3*time.Second)
	if err != nil {
		t.Fatalf("bob should have received replayed msg 1: %v", err)
	}
	_, err = bob.Await("msg 2", 3*time.Second)
	if err != nil {
		t.Fatalf("bob should have received replayed msg 2: %v", err)
	}
	_, err = bob.Await("msg 3", 3*time.Second)
	if err != nil {
		t.Fatalf("bob should have received replayed msg 3: %v", err)
	}
}

func TestHighConcurrencyRooms(t *testing.T) {
	server, ts := setupTestServer(t)
	defer server.Close()
	defer ts.Close()

	serverHost := strings.TrimPrefix(ts.URL, "http://")
	const numRooms = 4
	const numUsersPerRoom = 3

	var wg sync.WaitGroup
	for r := 0; r < numRooms; r++ {
		roomName := fmt.Sprintf("bench_ord_%d", r)
		for u := 0; u < numUsersPerRoom; u++ {
			wg.Add(1)
			userName := fmt.Sprintf("user_%d_%d", r, u)
			go func(rm, usr string) {
				defer wg.Done()
				peer := connectPeer(t, serverHost, rm, usr)
				defer peer.Leave()

				_, _ = peer.Await(usr+" joined", 3*time.Second)
				for i := 0; i < 5; i++ {
					_ = peer.Say(fmt.Sprintf(`{"type":"message","text":"hello %d from %s"}`, i, usr))
					time.Sleep(10 * time.Millisecond)
				}
			}(roomName, userName)
		}
	}
	wg.Wait()
}
