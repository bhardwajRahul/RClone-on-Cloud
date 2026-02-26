package rclone

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// --- JWT types ---

type contextKey string

const contextKeyClaims contextKey = "claims"

// Claims are the JWT claims carried through the request context.
type Claims struct {
	UserID string `json:"sub"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}

// GetClaims extracts claims from a request that passed through the bearer middleware.
func GetClaims(r *http.Request) *Claims {
	claims, _ := r.Context().Value(contextKeyClaims).(*Claims)
	return claims
}

// --- Handler ---

// ProxyHandler owns the JWT-protected reverse proxy.
type ProxyHandler struct {
	publicKey *rsa.PublicKey
	rcAddr    string
}

// NewProxyHandler prepares the JWT-protected proxy.
func NewProxyHandler(pubKeyPath string, rcAddr string) (*ProxyHandler, error) {
	publicKey, err := loadRSAPublicKey(pubKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load public key: %w", err)
	}

	return &ProxyHandler{publicKey: publicKey, rcAddr: rcAddr}, nil
}

// RegisterRoutes mounts the JWT-protected rclone proxy on the given mux.
func (h *ProxyHandler) RegisterRoutes(mux *http.ServeMux) {
	target, _ := url.Parse("http://" + h.rcAddr)
	proxy := httputil.NewSingleHostReverseProxy(target)
	mux.Handle("/api/v1/rclone/", bearerMiddleware(h.publicKey, http.StripPrefix("/api/v1/rclone", proxy)))
}

// --- Helpers ---

func loadRSAPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("public key file is not valid PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not an RSA public key")
	}
	return rsaPub, nil
}

// --- Middleware ---

func bearerMiddleware(publicKey *rsa.PublicKey, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, ok := extractBearer(r)
		if !ok {
			jsonError(w, "missing or malformed token", http.StatusUnauthorized)
			return
		}

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return publicKey, nil
		})

		if err != nil || !token.Valid {
			if errors.Is(err, jwt.ErrTokenExpired) {
				jsonError(w, "token expired", http.StatusUnauthorized)
				return
			}
			jsonError(w, "invalid token", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), contextKeyClaims, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func extractBearer(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", false
	}
	parts := strings.SplitN(h, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", false
	}
	tok := strings.TrimSpace(parts[1])
	if tok == "" {
		return "", false
	}
	return tok, true
}

func jsonError(w http.ResponseWriter, msg string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", `Bearer realm="rclone-api"`)
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"error":"%s"}`, msg)
}
