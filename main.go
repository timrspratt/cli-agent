// main.go
package main

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/creack/pty"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
)

// ---------- Embedded static terminal page ----------

//go:embed static/*
var staticFS embed.FS

// ---------- Global session tracking ----------

var activeSessions atomic.Int64 // number of active WS sessions

// ---------- JWT claims ----------

type Claims struct {
	jwt.RegisteredClaims
	TenantID string `json:"tenant_id"`
	ServerID string `json:"server_id"`
	// NOTE: we intentionally ignore any run_as claim for safety.
	// RunAs string `json:"run_as,omitempty"`
}

type ControlMsg struct {
	Type string `json:"type"`
	Cols int    `json:"cols,omitempty"`
	Rows int    `json:"rows,omitempty"`
}

// ---------- WebSocket upgrader ----------

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		// If you want strict origin checks, do it here.
		// When behind Cloudflare, Origin may be blank for WS; and when behind nginx, it's localhost.
		return true
	},
}

// ---------- Helpers ----------

func loadRSAPublicKey(pemPath string) (*rsa.PublicKey, error) {
	b, err := os.ReadFile(pemPath)
	if err != nil {
		return nil, err
	}
	key, err := jwt.ParseRSAPublicKeyFromPEM(b)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func getToken(r *http.Request) string {
	// 1) Authorization: Bearer <token>
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(h), "bearer ") {
		return strings.TrimSpace(h[7:])
	}

	// 2) Query string ?token=... (easy for browser WS)
	if t := r.URL.Query().Get("token"); t != "" {
		return t
	}

	// 3) Sec-WebSocket-Protocol: bearer,<token>
	// Browsers can set subprotocols; this avoids query-string logging later.
	proto := r.Header.Get("Sec-WebSocket-Protocol")
	if proto != "" {
		parts := strings.Split(proto, ",")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		if len(parts) >= 2 && strings.EqualFold(parts[0], "bearer") {
			return parts[1]
		}
	}

	return ""
}

func verifyToken(tokenString string, pub *rsa.PublicKey, expectedAud string, leeway time.Duration) (*Claims, error) {
	if tokenString == "" {
		return nil, errors.New("missing token")
	}

	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithAudience(expectedAud),
		jwt.WithIssuer("deploycli-dev"),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(leeway),
	)

	claims := &Claims{}
	_, err := parser.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (any, error) {
		return pub, nil
	})
	if err != nil {
		return nil, fmt.Errorf("token invalid: %w", err)
	}

	// Optional sanity checks. You can remove these for prototyping.
	if claims.ServerID == "" || claims.TenantID == "" {
		return nil, errors.New("token missing server_id/tenant_id")
	}

	return claims, nil
}

func lookupUser(username string) (*user.User, int, int, error) {
	u, err := user.Lookup(username)
	if err != nil {
		return nil, 0, 0, err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return nil, 0, 0, err
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return nil, 0, 0, err
	}
	return u, uid, gid, nil
}

// Spawn a login shell as a fixed, configured OS user.
// This is where we enforce "can't root up" by ignoring any token-provided run_as.
func spawnShell(fixedRunAs string) (*os.File, *exec.Cmd, error) {
	// Use absolute path; avoids PATH surprises.
	cmd := exec.Command("/usr/bin/bash", "-l")

	// Base environment
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")

	// Default: run as fixedRunAs (recommended: an unprivileged user)
	runAs := strings.TrimSpace(fixedRunAs)
	if runAs == "" {
		runAs = "deploycli"
	}

	// If you choose root explicitly, that's on purpose.
	if runAs != "root" {
		u, uid, gid, err := lookupUser(runAs)
		if err != nil {
			return nil, nil, fmt.Errorf("lookup user %q: %w", runAs, err)
		}

		// Drop OS credentials
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{
				Uid: uint32(uid),
				Gid: uint32(gid),
			},
		}

		// Ensure HOME/USER match the target user (prevents /root/.bash_profile errors)
		cmd.Env = append(cmd.Env,
			"HOME="+u.HomeDir,
			"USER="+u.Username,
			"LOGNAME="+u.Username,
			"SHELL=/usr/bin/bash",
		)
		cmd.Dir = u.HomeDir
	} else {
		// Root: ensure HOME sane
		if os.Getenv("HOME") == "" {
			cmd.Env = append(cmd.Env, "HOME=/root")
		}
		if cmd.Dir == "" {
			cmd.Dir = "/root"
		}
	}

	// IMPORTANT: do NOT set Setpgid:true here; it can cause EPERM in some environments.
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return nil, nil, err
	}
	return ptmx, cmd, nil
}

// ---------- Handlers ----------

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Basic hardening (tune as needed)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")

		// CSP:
		// - allow inline scripts for the embedded terminal prototype (quick fix)
		// - allow jsdelivr for sourcemap fetches (connect-src) so devtools isn't noisy
		w.Header().Set("Content-Security-Policy",
			"default-src 'self' https://cdn.jsdelivr.net; "+
				"script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "+
				"style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "+
				"connect-src 'self' wss: ws: https://cdn.jsdelivr.net; "+
				"img-src 'self' data:;")

		next.ServeHTTP(w, r)
	})
}

func wsHandler(pub *rsa.PublicKey, expectedAud string, leeway time.Duration, fixedRunAs string, requireProxyHeader bool, maxSession time.Duration, idleTimeout time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// If running behind nginx, enforce nginx marks the request.
		// In direct mode, set requireProxyHeader=false.
		if requireProxyHeader && r.Header.Get("X-DeployCLI-Proxy") != "1" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		claims, err := verifyToken(getToken(r), pub, expectedAud, leeway)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// Upgrade to websocket
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}

		remote := r.RemoteAddr

		// If behind Cloudflare or a proxy, prefer X-Forwarded-For
		if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
		    remote = strings.Split(xf, ",")[0]
		}

		log.Printf(
		    "session start server_id=%s tenant_id=%s remote=%s user=%s",
		    claims.ServerID,
		    claims.TenantID,
		    remote,
		    fixedRunAs,
		)

		// Track active sessions (used for optional agent auto-exit)
		activeSessions.Add(1)
		defer activeSessions.Add(-1)

		// Single-writer guard for gorilla/websocket (required).
		var writeMu sync.Mutex
		wsWrite := func(mt int, data []byte) error {
			writeMu.Lock()
			defer writeMu.Unlock()
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			return conn.WriteMessage(mt, data)
		}

		// Spawn session
		ptmx, cmd, err := spawnShell(fixedRunAs)
		if err != nil {
			log.Printf("spawnShell failed: %v", err)
			_ = wsWrite(websocket.TextMessage, []byte(`{"type":"exit","code":127}`))
			_ = conn.Close()
			return
		}

		// Session lifetime caps
		ctx, cancel := context.WithTimeout(context.Background(), maxSession)
		defer cancel()

		done := make(chan struct{})
		var cleanupOnce sync.Once

		safeCleanup := func(reason string, cerr error) {
			cleanupOnce.Do(func() {
				if cerr != nil {
					log.Printf("session end (%s) server_id=%s tenant_id=%s: %v", reason, claims.ServerID, claims.TenantID, cerr)
				} else {
					log.Printf("session end (%s) server_id=%s tenant_id=%s", reason, claims.ServerID, claims.TenantID)
				}

				close(done)

				// Close WS first to unblock ReadMessage immediately.
				_ = conn.Close()

				_ = ptmx.Close()
				if cmd.Process != nil {
					_ = cmd.Process.Kill()
				}
			})
		}
		defer safeCleanup("handler return", nil)

		// Kill on max-session timeout
		go func() {
			<-ctx.Done()
			safeCleanup("max session reached", ctx.Err())
		}()

		// Track last time we received a *client data message* (Text/Binary).
		// Do NOT update this from pong frames: you want "message comes in".
		lastClientMsgUnixNano := atomic.Int64{}
		lastClientMsgUnixNano.Store(time.Now().UnixNano())

		// Keep TCP reads from hanging forever on dead connections,
		// but don't let pongs count as "client sent a message".
		_ = conn.SetReadDeadline(time.Now().Add(idleTimeout))
		conn.SetPongHandler(func(string) error {
			_ = conn.SetReadDeadline(time.Now().Add(idleTimeout))
			return nil
		})

		// Idle killer: if no client messages arrive for idleTimeout, kill the process/session.
		go func() {
			t := time.NewTicker(2 * time.Second)
			defer t.Stop()

			for {
				select {
				case <-done:
					return
				case <-t.C:
					last := time.Unix(0, lastClientMsgUnixNano.Load())
					if time.Since(last) > idleTimeout {
						_ = wsWrite(websocket.TextMessage, []byte(`{"type":"exit","code":408}`))
						safeCleanup("idle timeout (no client messages)", nil)
						return
					}
				}
			}
		}()

		// Wait for shell exit to report code
		exitCh := make(chan int, 1)
		go func() {
			err := cmd.Wait()
			code := 0
			if err != nil {
				if ee, ok := err.(*exec.ExitError); ok {
					code = ee.ExitCode()
				} else {
					code = 255
				}
			}
			exitCh <- code
		}()

		// PTY -> WS (stop on any write error)
		go func() {
			buf := make([]byte, 8192)
			for {
				select {
				case <-done:
					return
				default:
				}

				n, err := ptmx.Read(buf)
				if n > 0 {
					if werr := wsWrite(websocket.BinaryMessage, buf[:n]); werr != nil {
						safeCleanup("ws write failed", werr)
						return
					}
				}
				if err != nil {
					// PTY closed or shell exited
					safeCleanup("pty read ended", err)
					return
				}
			}
		}()

		// WS -> PTY loop
		for {
			select {
			case <-done:
				return

			case code := <-exitCh:
				_ = wsWrite(websocket.TextMessage, []byte(fmt.Sprintf(`{"type":"exit","code":%d}`, code)))
				safeCleanup("shell exited", nil)
				return

			default:
				mt, msg, err := conn.ReadMessage()
				if err != nil {
					safeCleanup("ws disconnected/read failed", err)
					return
				}

				_ = conn.SetReadDeadline(time.Now().Add(idleTimeout))

				// NOTE: This counts *any* client message (text/binary) as activity.
				// If your frontend sends heartbeat "ping" messages and you do NOT want those
				// to keep the session alive, move this update inside the cases and exclude ping.
				lastClientMsgUnixNano.Store(time.Now().UnixNano())

				switch mt {
				case websocket.BinaryMessage:
					_, _ = ptmx.Write(msg)

				case websocket.TextMessage:
					var c ControlMsg
					if json.Unmarshal(msg, &c) == nil && c.Type == "resize" && c.Cols > 0 && c.Rows > 0 {
						_ = pty.Setsize(ptmx, &pty.Winsize{Cols: uint16(c.Cols), Rows: uint16(c.Rows)})
						continue
					}
					if strings.Contains(string(msg), `"type":"ping"`) {
						_ = wsWrite(websocket.TextMessage, []byte(`{"type":"pong"}`))
					}
				}
			}
		}
	}
}

func healthz(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }

func genJWT() {
	keyPath := flag.String("key", "", "RSA private key PEM path")
	serverID := flag.String("server", "", "server_id")
	tenantID := flag.String("tenant", "", "tenant_id")
	runAs := flag.String("runas", "", "run_as (optional)")
	aud := flag.String("aud", "deploycli-terminal", "audience")
	ttl := flag.Int("ttl", 60, "token ttl seconds")

	flag.Parse()

	if *keyPath == "" || *serverID == "" || *tenantID == "" {
		fmt.Println("missing required args: --key --server --tenant")
		os.Exit(1)
	}

	privPem, err := os.ReadFile(*keyPath)
	if err != nil {
		log.Fatal(err)
	}

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privPem)
	if err != nil {
		log.Fatal(err)
	}

	now := time.Now()

	claims := jwt.MapClaims{
		"server_id": *serverID,
		"tenant_id": *tenantID,
		"aud":       *aud,
		"iss":       "deploycli-dev",
		"nbf":       now.Unix(),
		"exp":       now.Add(time.Duration(*ttl) * time.Second).Unix(),
		"jti":       fmt.Sprintf("dev-%d-%d", now.Unix(), time.Now().UnixNano()),
	}

	if *runAs != "" {
		claims["run_as"] = *runAs
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	signed, err := token.SignedString(privKey)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(signed)
}

// ---------- Main ----------

func main() {
	if len(os.Args) > 1 && os.Args[1] == "gen-jwt" {
		os.Args = append([]string{os.Args[0]}, os.Args[2:]...)
		genJWT()
		return
	}

	var (
		listenAddr = flag.String("listen", "127.0.0.1:8088", "listen address (use 0.0.0.0:443 for direct mode)")
		jwtPubPEM  = flag.String("jwt-pub", "/etc/deploycli/jwt_pub.pem", "JWT RS256 public key PEM path")
		aud        = flag.String("aud", "deploycli-terminal", "expected JWT audience")
		leeway     = flag.Duration("leeway", 2*time.Second, "JWT exp leeway (clock skew tolerance)")
		runAs      = flag.String("run-as", "deploycli", "OS user to run shell as (root is allowed but not recommended)")
		maxSess    = flag.Duration("max-session", 2*time.Hour, "max session duration")
		idle       = flag.Duration("idle-timeout", 15*time.Minute, "idle timeout (no client messages)")

		// NEW: exit the whole agent if there are no active WS sessions for this long (0 disables).
		exitIfNoSessions = flag.Duration("exit-if-no-sessions", 0, "exit process if there are no active WS sessions for this duration (0 disables)")

		// TLS for direct mode
		tlsCert = flag.String("tls-cert", "", "TLS cert path (enable HTTPS if set)")
		tlsKey  = flag.String("tls-key", "", "TLS key path (enable HTTPS if set)")

		// Cloudflare Authenticated Origin Pulls (mTLS) for direct mode
		aopCA      = flag.String("aop-ca", "", "PEM path for Cloudflare Authenticated Origin Pull CA (enables mTLS verification when serving TLS)")
		requireAOP = flag.Bool("require-aop", false, "require Cloudflare Authenticated Origin Pulls mTLS (TLS direct mode only)")

		// Proxy header enforcement for nginx mode
		requireProxyHeader = flag.Bool("require-proxy-header", false, "require X-DeployCLI-Proxy=1 (set true behind nginx)")

		// Static serving
		staticPrefix = flag.String("static-prefix", "/", "URL prefix for static terminal UI (default /)")
	)
	flag.Parse()

	pub, err := loadRSAPublicKey(*jwtPubPEM)
	if err != nil {
		log.Fatalf("load pubkey: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthz)

	// WebSocket endpoint
	mux.Handle("/ws", wsHandler(pub, *aud, *leeway, *runAs, *requireProxyHeader, *maxSess, *idle))

	// Static assets
	// static/terminal.html is embedded. We serve it at "/" and "/terminal" by default.
	fs := http.FS(staticFS)
	fileServer := http.FileServer(fs)

	// If someone hits "/", serve terminal.html
	mux.HandleFunc(*staticPrefix, func(w http.ResponseWriter, r *http.Request) {
		// Normalize: if requesting "/" or "/terminal", serve the embedded terminal page
		if r.URL.Path == "/" || r.URL.Path == "/terminal" {
			r2 := new(http.Request)
			*r2 = *r
			r2.URL.Path = "/static/terminal.html"
			fileServer.ServeHTTP(w, r2)
			return
		}

		// Serve other embedded static files under /static/...
		if strings.HasPrefix(r.URL.Path, "/static/") {
			fileServer.ServeHTTP(w, r)
			return
		}

		http.NotFound(w, r)
	})

	handler := securityHeaders(mux)

	s := &http.Server{
		Handler: handler,
		// WS sessions are long-lived; keep these reasonable but not too small.
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	// Optional: exit the agent if there are no active sessions for N duration.
	if *exitIfNoSessions > 0 {
		go func() {
			t := time.NewTicker(1 * time.Second)
			defer t.Stop()

			zeroSince := time.Now()
			for range t.C {
				if activeSessions.Load() == 0 {
					if time.Since(zeroSince) >= *exitIfNoSessions {
						log.Printf("no active WS sessions for %s; exiting", *exitIfNoSessions)
						os.Exit(0)
					}
					continue
				}
				// At least one session is active; reset the timer.
				zeroSince = time.Now()
			}
		}()
	}

	ln, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatal(err)
	}

	// If TLS cert/key provided -> HTTPS (direct mode).
	if *tlsCert != "" || *tlsKey != "" {
		if *tlsCert == "" || *tlsKey == "" {
			log.Fatal("both -tls-cert and -tls-key are required to enable HTTPS")
		}

		// If requiring Cloudflare Authenticated Origin Pulls, enforce mTLS client cert verification.
		if *requireAOP {
			if *aopCA == "" {
				log.Fatal("-require-aop needs -aop-ca=/path/to/origin-pull-ca.pem")
			}

			caPEM, err := os.ReadFile(*aopCA)
			if err != nil {
				log.Fatalf("read aop ca: %v", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caPEM) {
				log.Fatal("failed to parse -aop-ca PEM")
			}

			s.TLSConfig = &tls.Config{
				MinVersion: tls.VersionTLS12,
				// Require a client cert and verify it chains to the provided CA pool.
				ClientAuth: tls.RequireAndVerifyClientCert,
				ClientCAs:  pool,
			}
		}

		log.Printf("deploycli-agent HTTPS listening on %s (direct mode), run-as=%s require-proxy-header=%v require-aop=%v exit-if-no-sessions=%s",
			*listenAddr, *runAs, *requireProxyHeader, *requireAOP, *exitIfNoSessions)

		log.Fatal(s.ServeTLS(ln, *tlsCert, *tlsKey))
	}

	// Otherwise plain HTTP (nginx mode).
	log.Printf("deploycli-agent HTTP listening on %s (behind nginx mode), run-as=%s require-proxy-header=%v exit-if-no-sessions=%s",
		*listenAddr, *runAs, *requireProxyHeader, *exitIfNoSessions)
	log.Fatal(s.Serve(ln))
}

