package mail

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/smtp"
	"net/textproto"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testPort    = 587
	testSSLPort = 465
)

var (
	testConn    = &net.TCPConn{}
	testTLSConn = tls.Client(testConn, &tls.Config{InsecureSkipVerify: true})
	testConfig  = &tls.Config{InsecureSkipVerify: true}
	testAuth    = smtp.PlainAuth("", testUser, testPwd, testHost)
)

func TestDialer(t *testing.T) {
	d := NewDialer(testHost, testPort, "user", "pwd")
	testSendMail(t, d, []string{
		"Extension STARTTLS",
		"StartTLS",
		"Extension AUTH",
		"Auth",
		"Mail " + testFrom,
		"Rcpt " + testTo1,
		"Rcpt " + testTo2,
		"Data",
		"Write message",
		"Close writer",
		"Quit",
		"Close",
	})
}

func TestDialerSSL(t *testing.T) {
	d := NewDialer(testHost, testSSLPort, "user", "pwd")
	testSendMail(t, d, []string{
		"Extension AUTH",
		"Auth",
		"Mail " + testFrom,
		"Rcpt " + testTo1,
		"Rcpt " + testTo2,
		"Data",
		"Write message",
		"Close writer",
		"Quit",
		"Close",
	})
}

func TestDialerConfig(t *testing.T) {
	d := NewDialer(testHost, testPort, "user", "pwd")
	d.LocalName = "test"
	d.TLSConfig = testConfig
	testSendMail(t, d, []string{
		"Hello test",
		"Extension STARTTLS",
		"StartTLS",
		"Extension AUTH",
		"Auth",
		"Mail " + testFrom,
		"Rcpt " + testTo1,
		"Rcpt " + testTo2,
		"Data",
		"Write message",
		"Close writer",
		"Quit",
		"Close",
	})
}

func TestDialerSSLConfig(t *testing.T) {
	d := NewDialer(testHost, testSSLPort, "user", "pwd")
	d.LocalName = "test"
	d.TLSConfig = testConfig
	testSendMail(t, d, []string{
		"Hello test",
		"Extension AUTH",
		"Auth",
		"Mail " + testFrom,
		"Rcpt " + testTo1,
		"Rcpt " + testTo2,
		"Data",
		"Write message",
		"Close writer",
		"Quit",
		"Close",
	})
}

func TestDialerNoStartTLS(t *testing.T) {
	d := NewDialer(testHost, testPort, "user", "pwd")
	d.StartTLSPolicy = NoStartTLS
	testSendMail(t, d, []string{
		"Extension AUTH",
		"Auth",
		"Mail " + testFrom,
		"Rcpt " + testTo1,
		"Rcpt " + testTo2,
		"Data",
		"Write message",
		"Close writer",
		"Quit",
		"Close",
	})
}

func TestDialerOpportunisticStartTLS(t *testing.T) {
	d := NewDialer(testHost, testPort, "user", "pwd")
	d.StartTLSPolicy = OpportunisticStartTLS
	testSendMail(t, d, []string{
		"Extension STARTTLS",
		"StartTLS",
		"Extension AUTH",
		"Auth",
		"Mail " + testFrom,
		"Rcpt " + testTo1,
		"Rcpt " + testTo2,
		"Data",
		"Write message",
		"Close writer",
		"Quit",
		"Close",
	})

	if OpportunisticStartTLS != 0 {
		t.Errorf("OpportunisticStartTLS: expected 0, got %d",
			OpportunisticStartTLS)
	}
}

func TestDialerOpportunisticStartTLSUnsupported(t *testing.T) {
	d := NewDialer(testHost, testPort, "user", "pwd")
	d.StartTLSPolicy = OpportunisticStartTLS
	testSendMailStartTLSUnsupported(t, d, []string{
		"Extension STARTTLS",
		"Extension AUTH",
		"Auth",
		"Mail " + testFrom,
		"Rcpt " + testTo1,
		"Rcpt " + testTo2,
		"Data",
		"Write message",
		"Close writer",
		"Quit",
		"Close",
	})
}

func TestDialerMandatoryStartTLS(t *testing.T) {
	d := NewDialer(testHost, testPort, "user", "pwd")
	d.StartTLSPolicy = MandatoryStartTLS
	testSendMail(t, d, []string{
		"Extension STARTTLS",
		"StartTLS",
		"Extension AUTH",
		"Auth",
		"Mail " + testFrom,
		"Rcpt " + testTo1,
		"Rcpt " + testTo2,
		"Data",
		"Write message",
		"Close writer",
		"Quit",
		"Close",
	})
}

func TestDialerMandatoryStartTLSUnsupported(t *testing.T) {
	d := NewDialer(testHost, testPort, "user", "pwd")
	d.StartTLSPolicy = MandatoryStartTLS

	testClient := &mockClient{
		t:        t,
		addr:     addr(d.Host, d.Port),
		config:   d.TLSConfig,
		startTLS: false,
		timeout:  true,
	}

	err := doTestSendMail(t, d, testClient, []string{
		"Extension STARTTLS",
	})

	if _, ok := err.(StartTLSUnsupportedError); !ok {
		t.Errorf("expected StartTLSUnsupportedError, but got: %s",
			reflect.TypeOf(err).Name())
	}

	expected := "gomail: MandatoryStartTLS required, " +
		"but SMTP server does not support STARTTLS"
	if err.Error() != expected {
		t.Errorf("expected %s, but got: %s", expected, err)
	}
}

func TestDialerNoAuth(t *testing.T) {
	d := &Dialer{
		Host: testHost,
		Port: testPort,
	}
	testSendMail(t, d, []string{
		"Extension STARTTLS",
		"StartTLS",
		"Mail " + testFrom,
		"Rcpt " + testTo1,
		"Rcpt " + testTo2,
		"Data",
		"Write message",
		"Close writer",
		"Quit",
		"Close",
	})
}

func TestDialerTimeout(t *testing.T) {
	d := &Dialer{
		Host:         testHost,
		Port:         testPort,
		RetryFailure: true,
	}
	testSendMailTimeout(t, d, []string{
		"Extension STARTTLS",
		"StartTLS",
		"Mail " + testFrom,
		"Extension STARTTLS",
		"StartTLS",
		"Mail " + testFrom,
		"Rcpt " + testTo1,
		"Rcpt " + testTo2,
		"Data",
		"Write message",
		"Close writer",
		"Quit",
		"Close",
	})
}

func TestDialerTimeoutNoRetry(t *testing.T) {
	d := &Dialer{
		Host:         testHost,
		Port:         testPort,
		RetryFailure: false,
	}
	testClient := &mockClient{
		t:        t,
		addr:     addr(d.Host, d.Port),
		config:   d.TLSConfig,
		startTLS: true,
		timeout:  true,
	}

	err := doTestSendMail(t, d, testClient, []string{
		"Extension STARTTLS",
		"StartTLS",
		"Mail " + testFrom,
		"Quit",
	})
	require.EqualError(t, err, "gomail: could not send email 1: EOF")
}

type mockClient struct {
	t        *testing.T
	i        int
	want     []string
	addr     string
	config   *tls.Config
	startTLS bool
	timeout  bool
}

func (c *mockClient) Hello(localName string) error {
	c.do("Hello " + localName)
	return nil
}

func (c *mockClient) Extension(ext string) (bool, string) {
	c.do("Extension " + ext)
	ok := true
	if ext == "STARTTLS" {
		ok = c.startTLS
	}
	return ok, ""
}

func (c *mockClient) StartTLS(config *tls.Config) error {
	assertConfig(c.t, config, c.config)
	c.do("StartTLS")
	return nil
}

func (c *mockClient) Auth(a smtp.Auth) error {
	if !reflect.DeepEqual(a, testAuth) {
		c.t.Errorf("Invalid auth, got %#v, want %#v", a, testAuth)
	}
	c.do("Auth")
	return nil
}

func (c *mockClient) Mail(from string) error {
	c.do("Mail " + from)
	if c.timeout {
		c.timeout = false
		return io.EOF
	}
	return nil
}

func (c *mockClient) Rcpt(to string) error {
	c.do("Rcpt " + to)
	return nil
}

func (c *mockClient) Data() (io.WriteCloser, error) {
	c.do("Data")
	return &mockWriter{c: c, want: testMsg}, nil
}

func (c *mockClient) Quit() error {
	c.do("Quit")
	return nil
}

func (c *mockClient) Close() error {
	c.do("Close")
	return nil
}

func (c *mockClient) do(cmd string) {
	if c.i >= len(c.want) {
		c.t.Fatalf("Invalid command %q", cmd)
	}

	if cmd != c.want[c.i] {
		c.t.Fatalf("Invalid command, got %q, want %q", cmd, c.want[c.i])
	}
	c.i++
}

type mockWriter struct {
	want string
	c    *mockClient
	buf  bytes.Buffer
}

func (w *mockWriter) Write(p []byte) (int, error) {
	if w.buf.Len() == 0 {
		w.c.do("Write message")
	}
	w.buf.Write(p)
	return len(p), nil
}

func (w *mockWriter) Close() error {
	compareBodies(w.c.t, w.buf.String(), w.want)
	w.c.do("Close writer")
	return nil
}

func testSendMail(t *testing.T, d *Dialer, want []string) {
	testClient := &mockClient{
		t:        t,
		addr:     addr(d.Host, d.Port),
		config:   d.TLSConfig,
		startTLS: true,
		timeout:  false,
	}

	require.NoError(t, doTestSendMail(t, d, testClient, want))
}

func testSendMailStartTLSUnsupported(t *testing.T, d *Dialer, want []string) {
	testClient := &mockClient{
		t:        t,
		addr:     addr(d.Host, d.Port),
		config:   d.TLSConfig,
		startTLS: false,
		timeout:  false,
	}

	require.NoError(t, doTestSendMail(t, d, testClient, want))
}

func testSendMailTimeout(t *testing.T, d *Dialer, want []string) {
	testClient := &mockClient{
		t:        t,
		addr:     addr(d.Host, d.Port),
		config:   d.TLSConfig,
		startTLS: true,
		timeout:  true,
	}

	require.NoError(t, doTestSendMail(t, d, testClient, want))
}

func doTestSendMail(t *testing.T, d *Dialer, testClient *mockClient, want []string) error {
	testClient.want = want

	d.DialFunc = func(_ context.Context, network, address string) (net.Conn, error) {
		require.Equal(t, "tcp", network)
		require.Equal(t, testClient.addr, address)
		return testConn, nil
	}

	origTLSClient, origSMTPNewClient := tlsClient, smtpNewClient
	t.Cleanup(func() { tlsClient, smtpNewClient = origTLSClient, origSMTPNewClient })

	tlsClient = func(conn net.Conn, config *tls.Config) *tls.Conn {
		require.Equal(t, testConn, conn)
		assertConfig(t, config, testClient.config)
		return testTLSConn
	}

	smtpNewClient = func(conn net.Conn, host string) (smtpClient, error) {
		if host != testHost {
			t.Errorf("Invalid host, got %q, want %q", host, testHost)
		}
		require.Equal(t, testHost, host)
		return testClient, nil
	}

	return d.DialAndSend(t.Context(), getTestMessage())
}

func assertConfig(t *testing.T, got, want *tls.Config) {
	if want == nil {
		want = &tls.Config{ServerName: testHost}
	}
	if got.ServerName != want.ServerName {
		t.Errorf("Invalid field ServerName in config, got %q, want %q", got.ServerName, want.ServerName)
	}
	if got.InsecureSkipVerify != want.InsecureSkipVerify {
		t.Errorf("Invalid field InsecureSkipVerify in config, got %v, want %v", got.InsecureSkipVerify, want.InsecureSkipVerify)
	}
}

func TestDialStopsAtContextDeadline(t *testing.T) {
	for _, tc := range []struct {
		name    string
		ssl     bool
		stallOn string
	}{
		{name: "before the greeting", stallOn: "CONNECT"},
		{name: "after EHLO", stallOn: "EHLO"},
		{name: "during the TLS handshake", ssl: true, stallOn: "CONNECT"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			port := startSMTPServer(t, stallOn(tc.stallOn, nil))
			d := NewDialer("127.0.0.1", port, "", "")
			d.SSL = tc.ssl

			ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
			defer cancel()

			start := time.Now()
			s, err := d.Dial(ctx)
			assert.Less(t, time.Since(start), 3*time.Second)
			assert.ErrorIs(t, err, context.DeadlineExceeded)
			assert.Nil(t, s)
		})
	}
}

func TestDialStopsWhenContextIsCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	port := startSMTPServer(t, stallOn("EHLO", cancel))

	start := time.Now()
	s, err := NewDialer("127.0.0.1", port, "", "").Dial(ctx)
	assert.Less(t, time.Since(start), 3*time.Second)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Nil(t, s)
}

func TestSendStopsAtContextDeadline(t *testing.T) {
	for _, tc := range []struct {
		name    string
		stallOn string
	}{
		{name: "after MAIL", stallOn: "MAIL"},
		{name: "after RCPT", stallOn: "RCPT"},
		{name: "after DATA", stallOn: "DATA"},
		{name: "after the message data", stallOn: "."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			port := startSMTPServer(t, stallOn(tc.stallOn, nil))
			s, err := NewDialer("127.0.0.1", port, "", "").Dial(t.Context())
			require.NoError(t, err)
			defer s.Close()

			ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
			defer cancel()

			start := time.Now()
			err = s.Send(ctx, testFrom, []string{testTo1}, getTestMessage())
			assert.Less(t, time.Since(start), 3*time.Second)
			assert.ErrorIs(t, err, context.DeadlineExceeded)
			var opErr *net.OpError
			assert.ErrorAs(t, err, &opErr)
		})
	}
}

func TestSendStopsWhenContextIsCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	port := startSMTPServer(t, stallOn("RCPT", cancel))
	s, err := NewDialer("127.0.0.1", port, "", "").Dial(t.Context())
	require.NoError(t, err)
	defer s.Close()

	start := time.Now()
	err = s.Send(ctx, testFrom, []string{testTo1}, getTestMessage())
	assert.Less(t, time.Since(start), 3*time.Second)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestSendRedialsOnlyWhileContextIsActive(t *testing.T) {
	for _, tc := range []struct {
		name      string
		cancel    bool
		wantConns int32
	}{
		{name: "context active", wantConns: 2},
		{name: "context canceled", cancel: true, wantConns: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			var conns, mails atomic.Int32
			port := startSMTPServer(t, func(event string) string {
				switch event {
				case "CONNECT":
					conns.Add(1)
				case "MAIL":
					if mails.Add(1) == 1 {
						if tc.cancel {
							cancel()
						}
						return hangUp
					}
				}
				return smtpReply(event)
			})

			d := NewDialer("127.0.0.1", port, "", "")
			// The dial function ignores ctx, so only Send can prevent the redial.
			d.DialFunc = func(_ context.Context, network, address string) (net.Conn, error) {
				return net.Dial(network, address)
			}
			s, err := d.Dial(t.Context())
			require.NoError(t, err)
			defer s.Close()

			err = s.Send(ctx, testFrom, []string{testTo1}, getTestMessage())
			if tc.cancel {
				assert.ErrorIs(t, err, context.Canceled)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tc.wantConns, conns.Load())
			assert.Equal(t, tc.wantConns, mails.Load())
		})
	}
}

func TestSendCloserOutlivesContexts(t *testing.T) {
	var mails atomic.Int32
	port := startSMTPServer(t, func(event string) string {
		if event == "MAIL" {
			mails.Add(1)
		}
		return smtpReply(event)
	})

	dialCtx, cancelDial := context.WithCancel(t.Context())
	s, err := NewDialer("127.0.0.1", port, "", "").Dial(dialCtx)
	require.NoError(t, err)
	cancelDial()

	for range 2 {
		ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
		require.NoError(t, s.Send(ctx, testFrom, []string{testTo1}, getTestMessage()))
		cancel()
	}
	require.NoError(t, s.Close())
	assert.Equal(t, int32(2), mails.Load())
}

func TestSendKeepsServerErrors(t *testing.T) {
	port := startSMTPServer(t, func(event string) string {
		if event == "RCPT" {
			return "550 5.1.1 No such user"
		}
		return smtpReply(event)
	})
	s, err := NewDialer("127.0.0.1", port, "", "").Dial(t.Context())
	require.NoError(t, err)
	defer s.Close()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	err = s.Send(ctx, testFrom, []string{testTo1}, getTestMessage())
	var protoErr *textproto.Error
	require.ErrorAs(t, err, &protoErr)
	assert.Equal(t, 550, protoErr.Code)
}

const (
	// stall makes the test SMTP server stop replying on a connection while it
	// keeps reading from it.
	stall = ""
	// hangUp makes the test SMTP server close a connection.
	hangUp = "hang up"
)

// startSMTPServer starts an SMTP server on 127.0.0.1 and returns its port. The
// server replies to each event on a connection with respond's result. The
// events are "CONNECT" for the greeting, the verb of each command, and "." for
// the end of the message data.
func startSMTPServer(t *testing.T, respond func(event string) string) int {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		conns  []net.Conn
		closed bool
	)
	t.Cleanup(func() {
		_ = l.Close()
		mu.Lock()
		closed = true
		for _, conn := range conns {
			_ = conn.Close()
		}
		mu.Unlock()
		wg.Wait()
	})

	wg.Go(func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			if closed {
				mu.Unlock()
				_ = conn.Close()
				return
			}
			conns = append(conns, conn)
			mu.Unlock()
			wg.Go(func() { serveSMTP(conn, respond) })
		}
	})

	return l.Addr().(*net.TCPAddr).Port
}

func serveSMTP(conn net.Conn, respond func(event string) string) {
	defer conn.Close()
	text := textproto.NewConn(conn)

	reply := func(event string) bool {
		switch r := respond(event); r {
		case stall:
			_, _ = io.Copy(io.Discard, conn)
			return false
		case hangUp:
			return false
		default:
			return text.PrintfLine("%s", r) == nil
		}
	}

	if !reply("CONNECT") {
		return
	}
	for {
		line, err := text.ReadLine()
		if err != nil {
			return
		}
		verb, _, _ := strings.Cut(strings.ToUpper(line), " ")
		if !reply(verb) || verb == "QUIT" {
			return
		}
		if verb == "DATA" {
			if _, err := text.ReadDotBytes(); err != nil || !reply(".") {
				return
			}
		}
	}
}

func smtpReply(event string) string {
	switch event {
	case "CONNECT":
		return "220 localhost ESMTP"
	case "EHLO", "HELO":
		return "250 localhost"
	case "DATA":
		return "354 End data with <CR><LF>.<CR><LF>"
	case "QUIT":
		return "221 Bye"
	default:
		return "250 OK"
	}
}

// stallOn returns a responder that replies like an SMTP server until event,
// where it calls hook, if set, and stalls.
func stallOn(event string, hook func()) func(string) string {
	return func(e string) string {
		if e != event {
			return smtpReply(e)
		}
		if hook != nil {
			hook()
		}
		return stall
	}
}
