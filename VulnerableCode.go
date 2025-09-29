package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/md5" // CHALLENGE 1: replace this use with HMAC-SHA256
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath" // CHALLENGE 2: use this safely to prevent path traversal
	"strconv"
	"strings"
	"time"
)

// ===============================
// Code Review Lab (Stdlib only)
// Starts HTTP server on 127.0.0.1:8081
// ===============================

type App struct {
	secret string // Loaded from env
}

var (
	// Intentionally simple "users" store (plaintext for the exercise)
	users = map[string]string{
		"admin": "admin123",
		"alice": "password",
		"bob":   "qwerty",
	}

	// CHALLENGE 3: data races — no locks/atomics on these shared vars
	visits int                // total visits (racy)
	stats  = map[string]int{} // per-user hits (racy)

	// Minimal templating with an UNSAFE passthrough used in /docs (CHALLENGE 2)
	tplBase = template.Must(template.New("base").Funcs(template.FuncMap{
		"unsafe": func(s string) template.HTML { return template.HTML(s) }, // do not use in prod
	}).Parse(`<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Go Code Review Lab</title>
    <style>
      body{font-family:system-ui,Segoe UI,Arial,sans-serif;background:#0a0f14;color:#e7eef7;margin:0}
      header,footer{background:#0d1117;padding:14px 18px}
      a{color:#8ab4f8;text-decoration:none}
      main{padding:20px}
      input,button,textarea{padding:8px;border-radius:8px;border:1px solid #333;background:#0f1720;color:#e7eef7}
      .card{background:#0d1117;border:1px solid #1f2937;border-radius:14px;padding:16px;margin:14px 0;box-shadow:0 4px 18px rgba(0,0,0,.25)}
      .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px}
      .muted{opacity:.8}
      .mono{font-family:ui-monospace,Consolas,monospace}
    </style>
  </head>
  <body>
    <header>
      <strong>Go Code Review Lab</strong>
      | <a href="/">Home</a>
      | <a href="/login">Login</a>
      | <a href="/profile">Profile</a>
      | <a href="/docs">Docs</a>
      | <a href="/counter">Counter</a>
      | <a href="/token">Token</a>
      | <a href="/debug">Debug</a>
    </header>
    <main>{{ template "content" . }}</main>
    <footer class="muted">For educational use in isolated labs. Do not deploy.</footer>
  </body>
</html>`))

	tplHome = template.Must(template.Must(tplBase.Clone()).Parse(`{{ define "content" }}
<div class="grid">
  <div class="card">
    <h3>Welcome</h3>
    <p>This mini app is designed for code review & fix practice.</p>
    <ul class="mono">
      <li>Login: /login</li>
      <li>View profile: /profile</li>
      <li>Docs viewer: /docs?name=sample.md</li>
      <li>Counter: /counter?user=alice&n=50</li>
      <li>Token: /token (requires login)</li>
      <li>Debug: /debug</li>
    </ul>
    <p>Sample users:</p>
    <ul>
      <li><strong>admin</strong> / <code>admin123</code></li>
      <li><strong>alice</strong> / <code>password</code></li>
      <li><strong>bob</strong> / <code>qwerty</code></li>
    </ul>
  </div>
  <div class="card">
    <h3>How to use</h3>
    <ol>
      <li>Browse endpoints and observe behaviors.</li>
      <li>Review the code (search for "CHALLENGE").</li>
      <li>Implement fixes and verify tests pass (see README section in comments).</li>
    </ol>
  </div>
</div>
{{ end }}`))

	tplLogin = template.Must(template.Must(tplBase.Clone()).Parse(`{{ define "content" }}
<div class="card">
  <h3>Login</h3>
  <form method="POST" action="/login">
    <div><input name="username" placeholder="username"></div>
    <div style="margin-top:8px"><input name="password" type="password" placeholder="password"></div>
    <div style="margin-top:12px"><button>Sign in</button></div>
  </form>
  <p class="muted">Tip: use a sample user from the home page.</p>
</div>
{{ end }}`))

	tplProfile = template.Must(template.Must(tplBase.Clone()).Parse(`{{ define "content" }}
<div class="card">
  <h3>Profile</h3>
  {{ if .User }}
    <p><strong>User:</strong> {{ .User }}</p>
    <p><a href="/logout">Logout</a></p>
  {{ else }}
    <p>You are not logged in. <a href="/login">Login</a></p>
  {{ end }}
</div>
{{ end }}`))

	tplDocs = template.Must(template.Must(tplBase.Clone()).Parse(`{{ define "content" }}
<div class="card">
  <h3>Docs Viewer</h3>
  <form method="GET" action="/docs" style="margin-bottom:8px">
    <input name="name" placeholder="sample.md"> <button>Open</button>
  </form>
  <div class="card">
    <div class="mono muted">docs/{{ .Name }}</div>
    <hr>
    <!-- CHALLENGE 2: Currently renders file content via |unsafe and allows arbitrary path -->
    <div>{{ .Content | unsafe }}</div>
  </div>
</div>
{{ end }}`))

	tplCounter = template.Must(template.Must(tplBase.Clone()).Parse(`{{ define "content" }}
<div class="card">
  <h3>Counter</h3>
  <form method="GET" action="/counter">
    <input name="user" placeholder="alice">
    <input name="n" placeholder="100">
    <button>Burst</button>
  </form>
  <p class="muted">Simulates concurrent increments; press multiple times or burst with ?n=100.</p>
  <pre class="mono">{{ .Body }}</pre>
</div>
{{ end }}`))

	tplToken = template.Must(template.Must(tplBase.Clone()).Parse(`{{ define "content" }}
<div class="card">
  <h3>API Token</h3>
  {{ if .User }}
    <p>Logged in as <strong>{{ .User }}</strong></p>
    <form method="POST" action="/token">
      <button>Generate Token</button>
    </form>
    {{ if .Token }}
      <p class="mono">Token: {{ .Token }}</p>
    {{ end }}
  {{ else }}
    <p>You are not logged in. <a href="/login">Login</a></p>
  {{ end }}
</div>
{{ end }}`))
)

func main() {
	secret := os.Getenv("SECRET_KEY")
	if secret == "" {
		log.Fatal("SECRET_KEY environment variable must be set")
	}
	app := &App{
		secret: secret,
	}
	ensureDocs()

	http.HandleFunc("/", app.handleHome)
	http.HandleFunc("/login", app.handleLogin)
	http.HandleFunc("/logout", app.handleLogout)
	http.HandleFunc("/profile", app.handleProfile)
	http.HandleFunc("/docs", app.handleDocs)     // CHALLENGE 2
	http.HandleFunc("/counter", app.handleCtr)   // CHALLENGE 3
	http.HandleFunc("/token", app.handleToken)   // CHALLENGE 1
	http.HandleFunc("/debug", app.handleDebug)   // exposes internals to help your review

	addr := "127.0.0.1:8081"
	log.Printf("Code Review Lab listening on http://%s\n", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

func ensureDocs() {
	_ = os.MkdirAll("docs", 0755)
	p := filepath.Join("docs", "sample.md")
	if _, err := os.Stat(p); os.IsNotExist(err) {
		_ = os.WriteFile(p, []byte("# Sample Doc\n\nThis is **sample.md**.\n\nTry editing it.\n"), 0644)
	}
}

// -------------------- Helpers --------------------

func currentUser(r *http.Request) string {
	c, err := r.Cookie("session")
	if err != nil || c.Value == "" {
		return ""
	}
	return c.Value
}

func setSession(w http.ResponseWriter, user string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    user,
		Path:     "/",
		HttpOnly: true,
		Secure:   true, // Set to true for HTTPS; for local dev, may need to adjust
		SameSite: http.SameSiteStrictMode,
	})
}

func clearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:    "session",
		Value:   "",
		Path:    "/",
		Expires: time.Unix(0, 0),
	})
}

func render(w http.ResponseWriter, tpl *template.Template, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tpl.ExecuteTemplate(w, "base", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// -------------------- Handlers --------------------

func (a *App) handleHome(w http.ResponseWriter, r *http.Request) {
	render(w, tplHome, nil)
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		render(w, tplLogin, nil)
	case "POST":
		_ = r.ParseForm()
		u := r.Form.Get("username")
		p := r.Form.Get("password")

		// Intentionally weak auth: plaintext compare + logs
		log.Printf("login attempt user=%s pass=%s", u, p) // ← do not log passwords in real apps
		if stored, ok := users[strings.ToLower(u)]; ok && subtle.ConstantTimeCompare([]byte(stored), []byte(p)) == 1 {
			setSession(w, strings.ToLower(u))
			http.Redirect(w, r, "/profile", http.StatusFound)
			return
		}
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	clearSession(w)
	http.Redirect(w, r, "/", http.StatusFound)
}

func (a *App) handleProfile(w http.ResponseWriter, r *http.Request) {
	render(w, tplProfile, map[string]any{"User": currentUser(r)})
}

// CHALLENGE 2: Path handling + unsafe rendering
func (a *App) handleDocs(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		name = "sample.md"
	}
	// Vulnerable path join: allows "../" to escape docs/
	path := "docs/" + name // TODO: fix with filepath.Clean + base check
	b, err := os.ReadFile(path)
	if err != nil {
		http.Error(w, "read error: "+err.Error(), http.StatusNotFound)
		return
	}
	// Renders file content directly as HTML (allows active markup)
	render(w, tplDocs, map[string]any{
		"Name":    name,
		"Content": string(b), // TODO: render safely (no |unsafe)
	})
}

// CHALLENGE 3: Data races (no locks around shared state)
func (a *App) handleCtr(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	if user == "" {
		user = "guest"
	}
	nStr := r.URL.Query().Get("n")
	if nStr == "" {
		nStr = "10"
	}
	n, _ := strconv.Atoi(nStr)
	if n < 1 {
		n = 1
	}
	// Simulate burst increments without synchronization
	done := make(chan struct{}, n)
	for i := 0; i < n; i++ {
		go func() {
			visits++           // racy write
			stats[user]++      // racy write
			time.Sleep(1e6)    // tiny delay
			done <- struct{}{}
		}()
	}
	for i := 0; i < n; i++ {
		<-done
	}

	// Build response
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Burst: %d\n", n))
	sb.WriteString(fmt.Sprintf("User: %s hits=%d\n", user, stats[user]))
	sb.WriteString(fmt.Sprintf("Total visits=%d\n", visits))
	render(w, tplCounter, map[string]any{"Body": sb.String()})
}

// CHALLENGE 1: Hardened token (HMAC-SHA256 with env secret)
func (a *App) makeToken(username string) string {
    ts := time.Now().Unix()
    mac := hmac.New(sha256.New, []byte(a.secret))
    mac.Write([]byte(username + ":" + strconv.FormatInt(ts, 10)))
    sig := hex.EncodeToString(mac.Sum(nil))
    return fmt.Sprintf("%s:%d:%s", username, ts, sig)
}

func (a *App) verifyToken(token string) bool {
    parts := strings.Split(token, ":")
    if len(parts) != 3 {
        return false
    }
    user := parts[0]
    ts := parts[1]
    sig := parts[2]
    mac := hmac.New(sha256.New, []byte(a.secret))
    mac.Write([]byte(user + ":" + ts))
    want := hex.EncodeToString(mac.Sum(nil))
    return subtle.ConstantTimeCompare([]byte(sig), []byte(want)) == 1
}

func (a *App) handleDebug(w http.ResponseWriter, r *http.Request) {
    io.WriteString(w, "== Debug ==\n")
    io.WriteString(w, fmt.Sprintf("users: %v\n", users))
    // Secret is no longer printed
    io.WriteString(w, fmt.Sprintf("visits=%d stats=%v\n", visits, stats))
}
