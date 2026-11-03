package helper

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func guarded(s *Server) http.Handler {
	return s.guard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
}

func TestGuard(t *testing.T) {
	cases := []struct {
		name, method, host, origin string
		internal                   bool
		want                       int
	}{
		{"panel on localhost", "POST", "127.0.0.1:18421", "http://localhost:8420", false, 200},
		{"panel on loopback", "GET", "127.0.0.1:18421", "http://127.0.0.1:8420", false, 200},
		{"named panel domain", "POST", "127.0.0.1:18421", "https://panel.example.com", false, 200},
		{"another website", "POST", "127.0.0.1:18421", "https://evil.example", false, 403},
		{"lookalike of the loopback name", "POST", "127.0.0.1:18421", "http://localhost.evil.example", false, 403},
		{"DNS rebinding", "GET", "evil.example:18421", "http://evil.example:18421", false, 403},
		{"no origin on a write", "POST", "127.0.0.1:18421", "", false, 403},
		{"no origin on a read", "GET", "127.0.0.1:18421", "", false, 200},
		{"backend on a Docker network", "POST", "kachat-nfc:18421", "", true, 200},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			server := &Server{AllowedOrigins: []string{"https://panel.example.com/"}, Internal: c.internal}
			request := httptest.NewRequest(c.method, "/v1/status", strings.NewReader(""))
			request.Host = c.host
			if c.origin != "" {
				request.Header.Set("Origin", c.origin)
			}
			recorder := httptest.NewRecorder()
			guarded(server).ServeHTTP(recorder, request)
			if recorder.Code != c.want {
				t.Fatalf("got %d, want %d", recorder.Code, c.want)
			}
		})
	}
}
