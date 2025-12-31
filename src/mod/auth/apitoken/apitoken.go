package apitoken

/*
	API Token Manager

	Provides standalone API tokens for programmatic access to Zoraxy.
	Tokens are not associated with users - they are system-level credentials
	with configurable permissions/scopes.
*/

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"

	"imuslab.com/zoraxy/mod/database"
)

// Permission scopes for API tokens
const (
	ScopeProxyRead     = "proxy:read"
	ScopeProxyWrite    = "proxy:write"
	ScopeVdirRead      = "vdir:read"
	ScopeVdirWrite     = "vdir:write"
	ScopeAccessRead    = "access:read"
	ScopeAccessWrite   = "access:write"
	ScopeRedirectRead  = "redirect:read"
	ScopeRedirectWrite = "redirect:write"
	ScopeCertRead      = "cert:read"
	ScopeCertWrite     = "cert:write"
	ScopeClusterRead   = "cluster:read"
	ScopeClusterWrite  = "cluster:write"
	ScopeAdmin         = "admin" // Full administrative access
	ScopeAll           = "*"
)

// Token prefix for identification
const TokenPrefix = "zrx_"

// Database table name
const TableName = "apitokens"

// ApiToken represents a stored API token (hashed)
type ApiToken struct {
	ID          string    `json:"id"`          // Unique identifier (UUID)
	Name        string    `json:"name"`        // Human-readable name
	TokenHash   string    `json:"-"`           // SHA256 hash of the token (never exposed)
	Scopes      []string  `json:"scopes"`      // Permission scopes
	CreatedAt   time.Time `json:"createdAt"`   // Creation timestamp
	LastUsedAt  time.Time `json:"lastUsedAt"`  // Last usage timestamp
	ExpiresAt   time.Time `json:"expiresAt"`   // Expiration (zero = never)
	Description string    `json:"description"` // Optional description
	Disabled    bool      `json:"disabled"`    // Whether token is disabled
}

// ClusterBroadcastFunc is a callback for broadcasting token changes to cluster
type ClusterBroadcastFunc func(tokenID, name, tokenHash, scopesJSON, description string, createdAt, expiresAt int64, disabled bool)

// ClusterDeleteFunc is a callback for broadcasting token deletions to cluster
type ClusterDeleteFunc func(tokenID string)

// TokenManager manages API tokens
type TokenManager struct {
	db              *database.Database
	cache           map[string]*ApiToken // hash -> token for fast lookup
	mutex           sync.RWMutex
	onBroadcast     ClusterBroadcastFunc // Called when token is created/updated
	onBroadcastDel  ClusterDeleteFunc    // Called when token is deleted
}

// NewTokenManager creates a new API token manager
func NewTokenManager(db *database.Database) (*TokenManager, error) {
	err := db.NewTable(TableName)
	if err != nil {
		return nil, err
	}

	tm := &TokenManager{
		db:    db,
		cache: make(map[string]*ApiToken),
	}

	// Load existing tokens into cache
	if err := tm.loadTokensToCache(); err != nil {
		return nil, err
	}

	return tm, nil
}

// SetClusterCallbacks sets the callbacks for cluster broadcasting
func (tm *TokenManager) SetClusterCallbacks(onBroadcast ClusterBroadcastFunc, onDelete ClusterDeleteFunc) {
	tm.onBroadcast = onBroadcast
	tm.onBroadcastDel = onDelete
}

// loadTokensToCache loads all tokens from database into memory cache
func (tm *TokenManager) loadTokensToCache() error {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	entries, err := tm.db.ListTable(TableName)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if len(entry) < 2 {
			continue
		}
		var token ApiToken
		if err := tm.db.Read(TableName, string(entry[0]), &token); err == nil {
			tm.cache[token.TokenHash] = &token
		}
	}

	return nil
}

// generateToken creates a cryptographically secure random token
func generateToken() (string, string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", "", err
	}

	// Create the raw token with prefix
	rawToken := TokenPrefix + hex.EncodeToString(bytes)

	// Hash the token for storage
	hash := sha256.Sum256([]byte(rawToken))
	tokenHash := hex.EncodeToString(hash[:])

	return rawToken, tokenHash, nil
}

// generateID creates a unique ID for the token
func generateID() (string, error) {
	bytes := make([]byte, 8)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// CreateToken creates a new API token and returns the raw token (only shown once)
func (tm *TokenManager) CreateToken(name string, scopes []string, description string, expiresAt time.Time) (*ApiToken, string, error) {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	// Generate token and hash
	rawToken, tokenHash, err := generateToken()
	if err != nil {
		return nil, "", err
	}

	// Generate unique ID
	id, err := generateID()
	if err != nil {
		return nil, "", err
	}

	// Create token record
	token := &ApiToken{
		ID:          id,
		Name:        name,
		TokenHash:   tokenHash,
		Scopes:      scopes,
		CreatedAt:   time.Now(),
		LastUsedAt:  time.Time{},
		ExpiresAt:   expiresAt,
		Description: description,
		Disabled:    false,
	}

	// Save to database
	if err := tm.db.Write(TableName, id, token); err != nil {
		return nil, "", err
	}

	// Add to cache
	tm.cache[tokenHash] = token

	return token, rawToken, nil
}

// ImportTokenFromCluster imports a token that was synchronized from another cluster node
// This uses the already-hashed token value since raw tokens are never shared between nodes
func (tm *TokenManager) ImportTokenFromCluster(id, name, tokenHash string, scopes []string, createdAt, expiresAt time.Time, description string, disabled bool) error {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	token := &ApiToken{
		ID:          id,
		Name:        name,
		TokenHash:   tokenHash,
		Scopes:      scopes,
		CreatedAt:   createdAt,
		LastUsedAt:  time.Time{},
		ExpiresAt:   expiresAt,
		Description: description,
		Disabled:    disabled,
	}

	// Save to database (will overwrite if exists)
	if err := tm.db.Write(TableName, id, token); err != nil {
		return err
	}

	// Update cache
	tm.cache[tokenHash] = token

	return nil
}

// GetTokenHash returns the hash for a token by ID (used for cluster sync)
func (tm *TokenManager) GetTokenHash(id string) (string, error) {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()

	var token ApiToken
	if err := tm.db.Read(TableName, id, &token); err != nil {
		return "", err
	}
	return token.TokenHash, nil
}

// ValidateToken validates a raw token and returns the token info if valid
func (tm *TokenManager) ValidateToken(rawToken string) (*ApiToken, error) {
	// Check prefix
	if !strings.HasPrefix(rawToken, TokenPrefix) {
		return nil, errors.New("invalid token format")
	}

	// Hash the provided token
	hash := sha256.Sum256([]byte(rawToken))
	tokenHash := hex.EncodeToString(hash[:])

	tm.mutex.RLock()
	token, exists := tm.cache[tokenHash]
	tm.mutex.RUnlock()

	if !exists {
		return nil, errors.New("invalid token")
	}

	// Check if disabled
	if token.Disabled {
		return nil, errors.New("token is disabled")
	}

	// Check expiration
	if !token.ExpiresAt.IsZero() && time.Now().After(token.ExpiresAt) {
		return nil, errors.New("token has expired")
	}

	// Update last used (async to not block validation)
	go tm.updateLastUsed(token.ID)

	return token, nil
}

// HasScope checks if a token has a specific scope
func (tm *TokenManager) HasScope(token *ApiToken, requiredScope string) bool {
	for _, scope := range token.Scopes {
		if scope == ScopeAll || scope == ScopeAdmin || scope == requiredScope {
			return true
		}
		// Check wildcard scopes (e.g., "proxy:*" matches "proxy:read")
		if strings.HasSuffix(scope, ":*") {
			prefix := strings.TrimSuffix(scope, "*")
			if strings.HasPrefix(requiredScope, prefix) {
				return true
			}
		}
	}
	return false
}

// updateLastUsed updates the last used timestamp
func (tm *TokenManager) updateLastUsed(id string) {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	var token ApiToken
	if err := tm.db.Read(TableName, id, &token); err != nil {
		return
	}

	token.LastUsedAt = time.Now()
	tm.db.Write(TableName, id, &token)

	// Update cache
	tm.cache[token.TokenHash] = &token
}

// ListTokens returns all tokens (without hashes)
func (tm *TokenManager) ListTokens() ([]*ApiToken, error) {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()

	tokens := make([]*ApiToken, 0, len(tm.cache))
	for _, token := range tm.cache {
		tokens = append(tokens, token)
	}
	return tokens, nil
}

// GetToken retrieves a token by ID
func (tm *TokenManager) GetToken(id string) (*ApiToken, error) {
	var token ApiToken
	if err := tm.db.Read(TableName, id, &token); err != nil {
		return nil, errors.New("token not found")
	}
	return &token, nil
}

// DeleteToken revokes/deletes a token by ID
func (tm *TokenManager) DeleteToken(id string) error {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	// Get token to find hash for cache removal
	var token ApiToken
	if err := tm.db.Read(TableName, id, &token); err != nil {
		return errors.New("token not found")
	}

	// Remove from database
	if err := tm.db.Delete(TableName, id); err != nil {
		return err
	}

	// Remove from cache
	delete(tm.cache, token.TokenHash)

	return nil
}

// DisableToken disables a token without deleting it
func (tm *TokenManager) DisableToken(id string, disabled bool) error {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	var token ApiToken
	if err := tm.db.Read(TableName, id, &token); err != nil {
		return errors.New("token not found")
	}

	token.Disabled = disabled

	if err := tm.db.Write(TableName, id, &token); err != nil {
		return err
	}

	// Update cache
	tm.cache[token.TokenHash] = &token

	return nil
}

// UpdateToken updates token name, description, or scopes
func (tm *TokenManager) UpdateToken(id string, name string, scopes []string, description string) error {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	var token ApiToken
	if err := tm.db.Read(TableName, id, &token); err != nil {
		return errors.New("token not found")
	}

	if name != "" {
		token.Name = name
	}
	if scopes != nil {
		token.Scopes = scopes
	}
	if description != "" {
		token.Description = description
	}

	if err := tm.db.Write(TableName, id, &token); err != nil {
		return err
	}

	// Update cache
	tm.cache[token.TokenHash] = &token

	return nil
}

