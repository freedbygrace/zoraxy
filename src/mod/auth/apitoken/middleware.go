package apitoken

/*
	API Token Middleware

	Provides HTTP middleware for authenticating API requests using tokens.
	Supports both Bearer token and X-API-Key header formats.
*/

import (
	"context"
	"net/http"
	"strings"
)

// Context keys for storing token info in request context
type contextKey string

const (
	ContextKeyToken contextKey = "apiToken"
)

// Middleware provides API token authentication middleware
type Middleware struct {
	tokenManager  *TokenManager
	deniedHandler http.HandlerFunc
}

// NewMiddleware creates a new API token middleware
func NewMiddleware(tm *TokenManager, deniedHandler http.HandlerFunc) *Middleware {
	return &Middleware{
		tokenManager:  tm,
		deniedHandler: deniedHandler,
	}
}

// extractToken extracts the API token from the request
// Supports: Authorization: Bearer <token> or X-API-Key: <token>
func (m *Middleware) extractToken(r *http.Request) string {
	// Check Authorization header first
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		if strings.HasPrefix(authHeader, "Bearer ") {
			return strings.TrimPrefix(authHeader, "Bearer ")
		}
	}

	// Check X-API-Key header
	apiKey := r.Header.Get("X-API-Key")
	if apiKey != "" {
		return apiKey
	}

	return ""
}

// Authenticate validates the API token and adds token info to request context
func (m *Middleware) Authenticate(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rawToken := m.extractToken(r)
		if rawToken == "" {
			m.deniedHandler(w, r)
			return
		}

		token, err := m.tokenManager.ValidateToken(rawToken)
		if err != nil {
			m.deniedHandler(w, r)
			return
		}

		// Add token to request context
		ctx := context.WithValue(r.Context(), ContextKeyToken, token)
		next(w, r.WithContext(ctx))
	}
}

// RequireScope creates a middleware that checks for a specific scope
func (m *Middleware) RequireScope(scope string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rawToken := m.extractToken(r)
		if rawToken == "" {
			m.deniedHandler(w, r)
			return
		}

		token, err := m.tokenManager.ValidateToken(rawToken)
		if err != nil {
			m.deniedHandler(w, r)
			return
		}

		// Check scope
		if !m.tokenManager.HasScope(token, scope) {
			http.Error(w, "403 - Forbidden: insufficient permissions", http.StatusForbidden)
			return
		}

		// Add token to request context
		ctx := context.WithValue(r.Context(), ContextKeyToken, token)
		next(w, r.WithContext(ctx))
	}
}

// GetTokenFromContext retrieves the API token from the request context
func GetTokenFromContext(r *http.Request) *ApiToken {
	token, ok := r.Context().Value(ContextKeyToken).(*ApiToken)
	if !ok {
		return nil
	}
	return token
}

// OptionalAuth attempts to authenticate but allows unauthenticated requests
// Useful for endpoints that behave differently for authenticated users
func (m *Middleware) OptionalAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rawToken := m.extractToken(r)
		if rawToken != "" {
			token, err := m.tokenManager.ValidateToken(rawToken)
			if err == nil {
				ctx := context.WithValue(r.Context(), ContextKeyToken, token)
				r = r.WithContext(ctx)
			}
		}
		next(w, r)
	}
}

