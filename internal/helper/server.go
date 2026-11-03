package helper

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultAddress is where the panel looks for the helper.
const DefaultAddress = "127.0.0.1:18421"

const maxRequestBody = 4096

// Server is the local HTTP service the panel talks to. Any website the user visits can try to reach
// a service on localhost, so it checks the Host header against DNS rebinding and only answers
// origins it was told about.
type Server struct {
	Service *Service
	// AllowedOrigins are extra origins, such as a Quick Start panel on its own domain. A loopback
	// origin on any port is always allowed.
	AllowedOrigins []string
	// Internal turns the Host check off and needs no Origin. It's for a container that's only
	// reachable on a private Docker network, behind the panel's backend.
	Internal bool
}

// ListenAndServe runs until the process stops.
func (s *Server) ListenAndServe(address string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/status", s.handleStatus)
	mux.HandleFunc("/v1/card/load", s.handleLoad)
	mux.HandleFunc("/v1/card/secure", s.handleSecure)
	server := &http.Server{
		Addr:              address,
		Handler:           s.guard(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      3 * time.Minute,
	}
	return server.ListenAndServe()
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

func hostOnly(hostPort string) string {
	if host, _, err := net.SplitHostPort(hostPort); err == nil {
		return host
	}
	return hostPort
}

func (s *Server) originAllowed(origin string) bool {
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Host == "" {
		return false
	}
	if isLoopbackHost(hostOnly(parsed.Host)) {
		return parsed.Scheme == "http" || parsed.Scheme == "https"
	}
	for _, allowed := range s.AllowedOrigins {
		if strings.EqualFold(strings.TrimRight(allowed, "/"), origin) {
			return true
		}
	}
	return false
}

func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.Internal && !isLoopbackHost(hostOnly(r.Host)) {
			writeError(w, http.StatusForbidden, fail("forbidden", "This helper only answers on this computer."))
			return
		}
		origin := r.Header.Get("Origin")
		if origin != "" {
			if !s.originAllowed(origin) {
				writeError(w, http.StatusForbidden, fail("forbidden_origin", "This site isn't allowed to use the helper."))
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
		} else if !s.Internal && r.Method != http.MethodGet {
			// Browsers always send Origin on a POST, so only a local tool gets here. It should use the CLI.
			writeError(w, http.StatusForbidden, fail("forbidden_origin", "Requests need an Origin header."))
			return
		}
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.Header().Set("Access-Control-Allow-Private-Network", "true")
			w.Header().Set("Access-Control-Max-Age", "600")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, code int, problem *Error) {
	writeJSON(w, code, map[string]any{"error": problem})
}

func writeFailure(w http.ResponseWriter, err error) {
	var problem *Error
	if errors.As(err, &problem) {
		code := http.StatusConflict
		if problem.Code == "bad_admin_key" {
			code = http.StatusBadRequest
		}
		writeError(w, code, problem)
		return
	}
	writeError(w, http.StatusInternalServerError, fail("card_error", "%s", err.Error()))
}

// readJSON requires JSON, which makes a browser send a preflight the origin check can refuse.
func readJSON(w http.ResponseWriter, r *http.Request, into any) bool {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, fail("method_not_allowed", "Use POST."))
		return false
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, fail("bad_request", "Send JSON."))
		return false
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(into); err != nil {
		writeError(w, http.StatusBadRequest, fail("bad_request", "That request couldn't be read."))
		return false
	}
	return true
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, fail("method_not_allowed", "Use GET."))
		return
	}
	status, err := s.Service.Status()
	if err != nil {
		writeFailure(w, err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) handleLoad(w http.ResponseWriter, r *http.Request) {
	var request LoadRequest
	if !readJSON(w, r, &request) {
		return
	}
	result, err := s.Service.Load(request)
	if err != nil {
		writeFailure(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleSecure(w http.ResponseWriter, r *http.Request) {
	var request SecureRequest
	if !readJSON(w, r, &request) {
		return
	}
	result, err := s.Service.Secure(request)
	if err != nil {
		writeFailure(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}
