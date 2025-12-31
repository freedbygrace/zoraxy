package apitoken

/*
	API Token HTTP Handlers

	Provides HTTP endpoints for managing API tokens.
	These endpoints are protected by session auth (for UI access).
*/

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"imuslab.com/zoraxy/mod/utils"
)

// CreateTokenRequest is the request body for creating a token
type CreateTokenRequest struct {
	Name        string   `json:"name"`
	Scopes      []string `json:"scopes"`
	Description string   `json:"description"`
	ExpiresIn   int      `json:"expiresIn"` // Seconds until expiration, 0 = never
	Expiry      string   `json:"expiry"`    // ISO 8601 date string (alternative to expiresIn)
}

// CreateTokenResponse is the response when creating a token
type CreateTokenResponse struct {
	Token    string    `json:"token"`    // Raw token (only shown once!)
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Scopes   []string  `json:"scopes"`
	ExpireAt time.Time `json:"expireAt"`
}

// TokenListItem is a token in the list response (no sensitive data)
type TokenListItem struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Scopes      []string  `json:"scopes"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"createdAt"`
	LastUsedAt  time.Time `json:"lastUsedAt"`
	ExpiresAt   time.Time `json:"expiresAt"`
	Disabled    bool      `json:"disabled"`
}

// HandleCreateToken handles POST /api/tokens - create a new API token
func (tm *TokenManager) HandleCreateToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req CreateTokenRequest

	// Support both JSON and form data
	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/json") {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			utils.SendErrorResponse(w, "invalid request body: "+err.Error())
			return
		}
	} else {
		// Form data
		req.Name = r.FormValue("name")
		req.Description = r.FormValue("description")
		scopesStr := r.FormValue("scopes")
		if scopesStr != "" {
			req.Scopes = strings.Split(scopesStr, ",")
		}
		// Parse expiresIn if provided
		if expiresInStr := r.FormValue("expiresIn"); expiresInStr != "" {
			var expiresIn int
			if _, err := json.Number(expiresInStr).Int64(); err == nil {
				expiresIn = int(json.Number(expiresInStr).String()[0])
			}
			req.ExpiresIn = expiresIn
		}
	}

	// Validate
	if req.Name == "" {
		utils.SendErrorResponse(w, "name is required")
		return
	}
	if len(req.Scopes) == 0 {
		utils.SendErrorResponse(w, "at least one scope is required")
		return
	}

	// Calculate expiration
	var expiresAt time.Time
	if req.Expiry != "" {
		// Parse ISO 8601 date string
		parsed, err := time.Parse(time.RFC3339, req.Expiry)
		if err != nil {
			utils.SendErrorResponse(w, "invalid expiry date format, use ISO 8601")
			return
		}
		expiresAt = parsed
	} else if req.ExpiresIn > 0 {
		expiresAt = time.Now().Add(time.Duration(req.ExpiresIn) * time.Second)
	}

	// Create token
	token, rawToken, err := tm.CreateToken(req.Name, req.Scopes, req.Description, expiresAt)
	if err != nil {
		utils.SendErrorResponse(w, "failed to create token: "+err.Error())
		return
	}

	// Broadcast to cluster
	tm.broadcastToken(token)

	// Return response with raw token (only time it's shown!)
	resp := CreateTokenResponse{
		Token:    rawToken,
		ID:       token.ID,
		Name:     token.Name,
		Scopes:   token.Scopes,
		ExpireAt: token.ExpiresAt,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// HandleListTokens handles GET /api/tokens - list all tokens
func (tm *TokenManager) HandleListTokens(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tokens, err := tm.ListTokens()
	if err != nil {
		utils.SendErrorResponse(w, "failed to list tokens: "+err.Error())
		return
	}

	// Convert to list items (hide sensitive data)
	items := make([]TokenListItem, 0, len(tokens))
	for _, t := range tokens {
		items = append(items, TokenListItem{
			ID:          t.ID,
			Name:        t.Name,
			Scopes:      t.Scopes,
			Description: t.Description,
			CreatedAt:   t.CreatedAt,
			LastUsedAt:  t.LastUsedAt,
			ExpiresAt:   t.ExpiresAt,
			Disabled:    t.Disabled,
		})
	}

	// Sort by creation date (newest first)
	sort.Slice(items, func(i, j int) bool {
		return items[i].CreatedAt.After(items[j].CreatedAt)
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(items)
}

// HandleDeleteToken handles DELETE /api/tokens?id=xxx - delete a token
func (tm *TokenManager) HandleDeleteToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" {
		id = r.FormValue("id")
	}
	if id == "" {
		utils.SendErrorResponse(w, "id is required")
		return
	}

	if err := tm.DeleteToken(id); err != nil {
		utils.SendErrorResponse(w, "failed to delete token: "+err.Error())
		return
	}

	// Broadcast deletion to cluster
	tm.broadcastTokenDelete(id)

	utils.SendOK(w)
}

// HandleToggleToken handles POST /api/tokens/toggle - enable/disable a token
func (tm *TokenManager) HandleToggleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := r.FormValue("id")
	if id == "" {
		utils.SendErrorResponse(w, "id is required")
		return
	}

	disabledStr := r.FormValue("disabled")
	disabled := disabledStr == "true" || disabledStr == "1"

	if err := tm.DisableToken(id, disabled); err != nil {
		utils.SendErrorResponse(w, "failed to toggle token: "+err.Error())
		return
	}

	// Broadcast toggle to cluster
	if token, err := tm.GetToken(id); err == nil {
		tm.broadcastToken(token)
	}

	utils.SendOK(w)
}

// HandleUpdateToken handles POST /api/tokens/update - update token metadata
func (tm *TokenManager) HandleUpdateToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := r.FormValue("id")
	if id == "" {
		utils.SendErrorResponse(w, "id is required")
		return
	}

	name := r.FormValue("name")
	description := r.FormValue("description")

	var scopes []string
	scopesStr := r.FormValue("scopes")
	if scopesStr != "" {
		scopes = strings.Split(scopesStr, ",")
	}

	if err := tm.UpdateToken(id, name, scopes, description); err != nil {
		utils.SendErrorResponse(w, "failed to update token: "+err.Error())
		return
	}

	// Broadcast update to cluster
	if token, err := tm.GetToken(id); err == nil {
		tm.broadcastToken(token)
	}

	utils.SendOK(w)
}

// HandleGetScopes handles GET /api/tokens/scopes - list available scopes
func (tm *TokenManager) HandleGetScopes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	scopes := []map[string]string{
		{"id": ScopeAll, "name": "Full Access", "description": "Access to all API endpoints"},
		{"id": ScopeProxyRead, "name": "Proxy Read", "description": "Read proxy rules"},
		{"id": ScopeProxyWrite, "name": "Proxy Write", "description": "Create/update/delete proxy rules"},
		{"id": ScopeVdirRead, "name": "Virtual Directory Read", "description": "Read virtual directories"},
		{"id": ScopeVdirWrite, "name": "Virtual Directory Write", "description": "Create/update/delete virtual directories"},
		{"id": ScopeAccessRead, "name": "Access Rules Read", "description": "Read access rules"},
		{"id": ScopeAccessWrite, "name": "Access Rules Write", "description": "Create/update/delete access rules"},
		{"id": ScopeRedirectRead, "name": "Redirect Read", "description": "Read redirect rules"},
		{"id": ScopeRedirectWrite, "name": "Redirect Write", "description": "Create/update/delete redirect rules"},
		{"id": ScopeCertRead, "name": "Certificate Read", "description": "Read certificates"},
		{"id": ScopeCertWrite, "name": "Certificate Write", "description": "Manage certificates"},
		{"id": ScopeClusterRead, "name": "Cluster Read", "description": "Read cluster status"},
		{"id": ScopeClusterWrite, "name": "Cluster Write", "description": "Manage cluster"},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scopes)
}

// broadcastToken broadcasts a token creation/update to the cluster
func (tm *TokenManager) broadcastToken(token *ApiToken) {
	if tm.onBroadcast == nil || token == nil {
		return
	}

	// Encode scopes as JSON
	scopesJSON, _ := json.Marshal(token.Scopes)

	var expiresAt int64
	if !token.ExpiresAt.IsZero() {
		expiresAt = token.ExpiresAt.Unix()
	}

	tm.onBroadcast(
		token.ID,
		token.Name,
		token.TokenHash,
		string(scopesJSON),
		token.Description,
		token.CreatedAt.Unix(),
		expiresAt,
		token.Disabled,
	)
}

// broadcastTokenDelete broadcasts a token deletion to the cluster
func (tm *TokenManager) broadcastTokenDelete(tokenID string) {
	if tm.onBroadcastDel == nil {
		return
	}
	tm.onBroadcastDel(tokenID)
}
