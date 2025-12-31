package main

/*
	REST API v1

	Provides versioned REST API endpoints for programmatic access.
	All endpoints under /api/v1/ require API token authentication.
*/

import (
	"encoding/json"
	"net/http"
	"strings"

	"imuslab.com/zoraxy/mod/access"
	"imuslab.com/zoraxy/mod/auth/apitoken"
	"imuslab.com/zoraxy/mod/dynamicproxy"
	"imuslab.com/zoraxy/mod/dynamicproxy/loadbalance"
	"imuslab.com/zoraxy/mod/utils"
)

// APIv1Router handles /api/v1/ endpoints with API token authentication
type APIv1Router struct {
	mux        *http.ServeMux
	middleware *apitoken.Middleware
}

// NewAPIv1Router creates a new API v1 router
func NewAPIv1Router(tokenManager *apitoken.TokenManager) *APIv1Router {
	mux := http.NewServeMux()
	middleware := apitoken.NewMiddleware(tokenManager, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "unauthorized",
			"message": "Valid API token required. Use Authorization: Bearer <token> header.",
		})
	})

	router := &APIv1Router{
		mux:        mux,
		middleware: middleware,
	}

	// Register routes
	router.registerStatusRoutes()
	router.registerDocsRoutes()
	router.registerProxyRoutes()
	router.registerVdirRoutes()
	router.registerAccessRuleRoutes()
	router.registerRedirectRoutes()
	router.registerCertRoutes()
	router.registerClusterRoutes()

	return router
}

// ServeHTTP implements http.Handler
func (r *APIv1Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// Check if REST API is enabled (dynamic check - no restart needed)
	if !isRestAPIEnabled() {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "service unavailable",
			"message": "REST API is disabled. Enable it in the web UI under Others > Rest API.",
		})
		return
	}

	// Set JSON content type for all API responses
	w.Header().Set("Content-Type", "application/json")
	r.mux.ServeHTTP(w, req)
}

// registerStatusRoutes registers status/health endpoints
func (r *APIv1Router) registerStatusRoutes() {
	// Status endpoint - no auth required for basic health check
	r.mux.HandleFunc("/api/v1/status", r.handleStatus)
}

// handleStatus handles GET /api/v1/status - returns system status
func (r *APIv1Router) handleStatus(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	status := map[string]interface{}{
		"status":  "ok",
		"version": SYSTEM_VERSION,
	}

	json.NewEncoder(w).Encode(status)
}

// registerProxyRoutes registers proxy CRUD endpoints
func (r *APIv1Router) registerProxyRoutes() {
	// List all proxies
	r.mux.HandleFunc("/api/v1/proxies", r.middleware.RequireScope(apitoken.ScopeProxyRead, r.handleProxies))
	// Single proxy operations
	r.mux.HandleFunc("/api/v1/proxies/", r.handleProxyByID)
}

// registerVdirRoutes registers virtual directory CRUD endpoints
func (r *APIv1Router) registerVdirRoutes() {
	r.mux.HandleFunc("/api/v1/vdirs", r.middleware.RequireScope(apitoken.ScopeVdirRead, r.handleVdirs))
	r.mux.HandleFunc("/api/v1/vdirs/", r.handleVdirByID)
}

// handleProxies handles GET /api/v1/proxies - list all proxy rules
func (r *APIv1Router) handleProxies(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// Get all proxy endpoints
	endpoints := dynamicProxyRouter.GetProxyEndpointsAsMap()

	// Build response
	type ProxyResponse struct {
		RootOrMatchingDomain string   `json:"rootOrMatchingDomain"`
		ProxyType            int      `json:"proxyType"`
		Disabled             bool     `json:"disabled"`
		ActiveOrigins        []string `json:"activeOrigins"`
		InactiveOrigins      []string `json:"inactiveOrigins"`
		BypassGlobalTLS      bool     `json:"bypassGlobalTLS"`
	}

	response := []ProxyResponse{}
	for _, ep := range endpoints {
		activeOrigins := []string{}
		inactiveOrigins := []string{}
		for _, origin := range ep.ActiveOrigins {
			activeOrigins = append(activeOrigins, origin.OriginIpOrDomain)
		}
		for _, origin := range ep.InactiveOrigins {
			inactiveOrigins = append(inactiveOrigins, origin.OriginIpOrDomain)
		}

		response = append(response, ProxyResponse{
			RootOrMatchingDomain: ep.RootOrMatchingDomain,
			ProxyType:            int(ep.ProxyType),
			Disabled:             ep.Disabled,
			ActiveOrigins:        activeOrigins,
			InactiveOrigins:      inactiveOrigins,
			BypassGlobalTLS:      ep.BypassGlobalTLS,
		})
	}

	json.NewEncoder(w).Encode(response)
}

// handleProxyByID handles single proxy operations
func (r *APIv1Router) handleProxyByID(w http.ResponseWriter, req *http.Request) {
	// Extract proxy ID from path
	path := strings.TrimPrefix(req.URL.Path, "/api/v1/proxies/")
	if path == "" {
		http.Error(w, `{"error":"proxy ID required"}`, http.StatusBadRequest)
		return
	}

	switch req.Method {
	case http.MethodGet:
		r.middleware.RequireScope(apitoken.ScopeProxyRead, func(w http.ResponseWriter, req *http.Request) {
			r.getProxy(w, req, path)
		})(w, req)
	case http.MethodPost, http.MethodPut:
		r.middleware.RequireScope(apitoken.ScopeProxyWrite, func(w http.ResponseWriter, req *http.Request) {
			r.upsertProxy(w, req, path)
		})(w, req)
	case http.MethodDelete:
		r.middleware.RequireScope(apitoken.ScopeProxyWrite, func(w http.ResponseWriter, req *http.Request) {
			r.deleteProxy(w, req, path)
		})(w, req)
	default:
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

// getProxy retrieves a single proxy by its matching domain
func (r *APIv1Router) getProxy(w http.ResponseWriter, req *http.Request, domain string) {
	ep, err := dynamicProxyRouter.LoadProxy(domain)
	if err != nil {
		http.Error(w, `{"error":"proxy not found"}`, http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(ep)
}

// ProxyCreateRequest is the request body for creating/updating a proxy
type ProxyCreateRequest struct {
	Type            string   `json:"type"`            // "host" or "root"
	RootOrDomain    string   `json:"rootOrDomain"`    // Matching domain for host type
	Origins         []string `json:"origins"`         // List of origin servers
	RequireTLS      bool     `json:"requireTLS"`      // Use TLS for upstream
	SkipCertValid   bool     `json:"skipCertValid"`   // Skip TLS cert validation
	BypassGlobalTLS bool     `json:"bypassGlobalTLS"` // Bypass global TLS setting
	Disabled        bool     `json:"disabled"`        // Whether the proxy is disabled
}

// upsertProxy creates or updates a proxy rule
func (r *APIv1Router) upsertProxy(w http.ResponseWriter, req *http.Request, domain string) {
	var proxyReq ProxyCreateRequest
	if err := json.NewDecoder(req.Body).Decode(&proxyReq); err != nil {
		utils.SendErrorResponse(w, "invalid request body: "+err.Error())
		return
	}

	// Build origins using loadbalance.Upstream
	var activeOrigins []*loadbalance.Upstream
	for i, origin := range proxyReq.Origins {
		activeOrigins = append(activeOrigins, &loadbalance.Upstream{
			OriginIpOrDomain:    origin,
			RequireTLS:          proxyReq.RequireTLS,
			SkipCertValidations: proxyReq.SkipCertValid,
			Weight:              1,
			MaxConn:             0,
		})
		_ = i // avoid unused variable
	}

	// Create the endpoint using default values
	newEndpoint := dynamicproxy.GetDefaultProxyEndpoint()
	newEndpoint.ProxyType = dynamicproxy.ProxyTypeHost
	newEndpoint.RootOrMatchingDomain = domain
	newEndpoint.ActiveOrigins = activeOrigins
	newEndpoint.InactiveOrigins = []*loadbalance.Upstream{}
	newEndpoint.Disabled = proxyReq.Disabled
	newEndpoint.BypassGlobalTLS = proxyReq.BypassGlobalTLS

	if proxyReq.Type == "root" {
		newEndpoint.ProxyType = dynamicproxy.ProxyTypeRoot
	}

	// Prepare and add the route
	preparedRoute, err := dynamicProxyRouter.PrepareProxyRoute(&newEndpoint)
	if err != nil {
		utils.SendErrorResponse(w, "failed to prepare proxy route: "+err.Error())
		return
	}

	// Check if updating existing
	existingEp, _ := dynamicProxyRouter.LoadProxy(domain)
	if existingEp != nil {
		existingEp.Remove()
	}

	dynamicProxyRouter.AddProxyRouteToRuntime(preparedRoute)

	// Save to file
	if err := SaveReverseProxyConfig(&newEndpoint); err != nil {
		utils.SendErrorResponse(w, "failed to save proxy config: "+err.Error())
		return
	}

	// Broadcast to cluster if enabled
	if clusterManager != nil {
		go clusterManager.BroadcastProxyUpsert(req.Context(), &newEndpoint)
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "domain": domain})
}

// deleteProxy deletes a proxy rule
func (r *APIv1Router) deleteProxy(w http.ResponseWriter, req *http.Request, domain string) {
	ep, err := dynamicProxyRouter.LoadProxy(domain)
	if err != nil {
		http.Error(w, `{"error":"proxy not found"}`, http.StatusNotFound)
		return
	}

	// Remove from runtime
	ep.Remove()

	// Remove config file
	if err := RemoveReverseProxyConfig(domain); err != nil {
		utils.SendErrorResponse(w, "failed to remove proxy config: "+err.Error())
		return
	}

	// Broadcast to cluster if enabled
	if clusterManager != nil {
		go clusterManager.BroadcastProxyDelete(req.Context(), domain)
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "deleted": domain})
}

// handleVdirs handles virtual directory list operations
func (r *APIv1Router) handleVdirs(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// Get proxy domain from query parameter
	proxyDomain := req.URL.Query().Get("proxy")
	if proxyDomain == "" {
		proxyDomain = "root"
	}

	var ep *dynamicproxy.ProxyEndpoint
	var err error
	if proxyDomain == "root" {
		ep = dynamicProxyRouter.Root
	} else {
		ep, err = dynamicProxyRouter.LoadProxy(proxyDomain)
		if err != nil {
			http.Error(w, `{"error":"proxy not found"}`, http.StatusNotFound)
			return
		}
	}

	json.NewEncoder(w).Encode(ep.VirtualDirectories)
}

// handleVdirByID handles single virtual directory operations
func (r *APIv1Router) handleVdirByID(w http.ResponseWriter, req *http.Request) {
	// Parse path: /api/v1/vdirs/{proxyDomain}/{vdirPath}
	path := strings.TrimPrefix(req.URL.Path, "/api/v1/vdirs/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) < 1 {
		http.Error(w, `{"error":"proxy domain required"}`, http.StatusBadRequest)
		return
	}

	proxyDomain := parts[0]
	vdirPath := "/"
	if len(parts) > 1 {
		vdirPath = "/" + parts[1]
		if !strings.HasSuffix(vdirPath, "/") {
			vdirPath += "/"
		}
	}

	switch req.Method {
	case http.MethodGet:
		r.middleware.RequireScope(apitoken.ScopeVdirRead, func(w http.ResponseWriter, req *http.Request) {
			r.getVdir(w, req, proxyDomain, vdirPath)
		})(w, req)
	case http.MethodPost, http.MethodPut:
		r.middleware.RequireScope(apitoken.ScopeVdirWrite, func(w http.ResponseWriter, req *http.Request) {
			r.upsertVdir(w, req, proxyDomain, vdirPath)
		})(w, req)
	case http.MethodDelete:
		r.middleware.RequireScope(apitoken.ScopeVdirWrite, func(w http.ResponseWriter, req *http.Request) {
			r.deleteVdir(w, req, proxyDomain, vdirPath)
		})(w, req)
	default:
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

// getVdir retrieves a virtual directory
func (r *APIv1Router) getVdir(w http.ResponseWriter, req *http.Request, proxyDomain, vdirPath string) {
	var ep *dynamicproxy.ProxyEndpoint
	var err error
	if proxyDomain == "root" {
		ep = dynamicProxyRouter.Root
	} else {
		ep, err = dynamicProxyRouter.LoadProxy(proxyDomain)
		if err != nil {
			http.Error(w, `{"error":"proxy not found"}`, http.StatusNotFound)
			return
		}
	}

	vdir := ep.GetVirtualDirectoryRuleByMatchingPath(vdirPath)
	if vdir == nil {
		http.Error(w, `{"error":"virtual directory not found"}`, http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(vdir)
}

// VdirCreateRequest is the request body for creating/updating a vdir
type VdirCreateRequest struct {
	MatchingPath        string `json:"matchingPath"`
	Domain              string `json:"domain"`       // Target domain
	RequireTLS          bool   `json:"requireTLS"`
	SkipCertValidations bool   `json:"skipCertValidations"`
	Disabled            bool   `json:"disabled"`
}

// upsertVdir creates or updates a virtual directory
func (r *APIv1Router) upsertVdir(w http.ResponseWriter, req *http.Request, proxyDomain, vdirPath string) {
	var vdirReq VdirCreateRequest
	if err := json.NewDecoder(req.Body).Decode(&vdirReq); err != nil {
		utils.SendErrorResponse(w, "invalid request body: "+err.Error())
		return
	}

	// Use path from URL if not specified in body
	if vdirReq.MatchingPath == "" {
		vdirReq.MatchingPath = vdirPath
	}

	var ep *dynamicproxy.ProxyEndpoint
	var err error
	if proxyDomain == "root" {
		ep = dynamicProxyRouter.Root
	} else {
		ep, err = dynamicProxyRouter.LoadProxy(proxyDomain)
		if err != nil {
			http.Error(w, `{"error":"proxy not found"}`, http.StatusNotFound)
			return
		}
	}

	// Check if vdir exists (update) or new (create)
	existingVdir := ep.GetVirtualDirectoryRuleByMatchingPath(vdirReq.MatchingPath)
	if existingVdir != nil {
		ep.RemoveVirtualDirectoryRuleByMatchingPath(vdirReq.MatchingPath)
	}

	newVdir := &dynamicproxy.VirtualDirectoryEndpoint{
		MatchingPath:        vdirReq.MatchingPath,
		Domain:              vdirReq.Domain,
		RequireTLS:          vdirReq.RequireTLS,
		SkipCertValidations: vdirReq.SkipCertValidations,
		Disabled:            vdirReq.Disabled,
	}

	activatedEp, err := ep.AddVirtualDirectoryRule(newVdir)
	if err != nil {
		utils.SendErrorResponse(w, "failed to add virtual directory: "+err.Error())
		return
	}

	// Save to file
	if err := SaveReverseProxyConfig(activatedEp); err != nil {
		utils.SendErrorResponse(w, "failed to save config: "+err.Error())
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "path": vdirReq.MatchingPath})
}

// deleteVdir deletes a virtual directory
func (r *APIv1Router) deleteVdir(w http.ResponseWriter, req *http.Request, proxyDomain, vdirPath string) {
	var ep *dynamicproxy.ProxyEndpoint
	var err error
	if proxyDomain == "root" {
		ep = dynamicProxyRouter.Root
	} else {
		ep, err = dynamicProxyRouter.LoadProxy(proxyDomain)
		if err != nil {
			http.Error(w, `{"error":"proxy not found"}`, http.StatusNotFound)
			return
		}
	}

	// Check if vdir exists
	if ep.GetVirtualDirectoryRuleByMatchingPath(vdirPath) == nil {
		http.Error(w, `{"error":"virtual directory not found"}`, http.StatusNotFound)
		return
	}

	ep.RemoveVirtualDirectoryRuleByMatchingPath(vdirPath)

	// Save to file
	if err := SaveReverseProxyConfig(ep); err != nil {
		utils.SendErrorResponse(w, "failed to save config: "+err.Error())
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "deleted": vdirPath})
}

// ==================== Access Rules REST API ====================

// registerAccessRuleRoutes registers access rule CRUD endpoints
func (r *APIv1Router) registerAccessRuleRoutes() {
	r.mux.HandleFunc("/api/v1/access-rules", r.middleware.RequireScope(apitoken.ScopeAccessRead, r.handleAccessRules))
	r.mux.HandleFunc("/api/v1/access-rules/", r.handleAccessRuleByID)
}

// handleAccessRules handles GET /api/v1/access-rules - list all access rules
func (r *APIv1Router) handleAccessRules(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	rules := accessController.ListAllAccessRules()
	json.NewEncoder(w).Encode(rules)
}

// handleAccessRuleByID handles single access rule operations
func (r *APIv1Router) handleAccessRuleByID(w http.ResponseWriter, req *http.Request) {
	ruleID := strings.TrimPrefix(req.URL.Path, "/api/v1/access-rules/")
	if ruleID == "" {
		http.Error(w, `{"error":"rule ID required"}`, http.StatusBadRequest)
		return
	}

	switch req.Method {
	case http.MethodGet:
		r.middleware.RequireScope(apitoken.ScopeAccessRead, func(w http.ResponseWriter, req *http.Request) {
			r.getAccessRule(w, req, ruleID)
		})(w, req)
	case http.MethodPost, http.MethodPut:
		r.middleware.RequireScope(apitoken.ScopeAccessWrite, func(w http.ResponseWriter, req *http.Request) {
			r.upsertAccessRule(w, req, ruleID)
		})(w, req)
	case http.MethodDelete:
		r.middleware.RequireScope(apitoken.ScopeAccessWrite, func(w http.ResponseWriter, req *http.Request) {
			r.deleteAccessRule(w, req, ruleID)
		})(w, req)
	default:
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

// getAccessRule retrieves a single access rule
func (r *APIv1Router) getAccessRule(w http.ResponseWriter, req *http.Request, ruleID string) {
	rule, err := accessController.GetAccessRuleByID(ruleID)
	if err != nil {
		http.Error(w, `{"error":"access rule not found"}`, http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(rule)
}

// AccessRuleCreateRequest is the request body for creating/updating an access rule
type AccessRuleCreateRequest struct {
	Name             string `json:"name"`
	Desc             string `json:"desc"`
	BlacklistEnabled bool   `json:"blacklistEnabled"`
	WhitelistEnabled bool   `json:"whitelistEnabled"`
}

// upsertAccessRule creates or updates an access rule
func (r *APIv1Router) upsertAccessRule(w http.ResponseWriter, req *http.Request, ruleID string) {
	var ruleReq AccessRuleCreateRequest
	if err := json.NewDecoder(req.Body).Decode(&ruleReq); err != nil {
		utils.SendErrorResponse(w, "invalid request body: "+err.Error())
		return
	}

	// Check if rule exists
	existingRule, _ := accessController.GetAccessRuleByID(ruleID)
	if existingRule != nil {
		// Update existing
		if err := accessController.UpdateAccessRule(ruleID, ruleReq.Name, ruleReq.Desc); err != nil {
			utils.SendErrorResponse(w, "failed to update access rule: "+err.Error())
			return
		}
		// Update enabled flags
		existingRule.ToggleBlacklist(ruleReq.BlacklistEnabled)
		existingRule.ToggleWhitelist(ruleReq.WhitelistEnabled)
	} else {
		// Create new with the provided ID
		newRule := &access.AccessRule{
			ID:               ruleID,
			Name:             ruleReq.Name,
			Desc:             ruleReq.Desc,
			BlacklistEnabled: ruleReq.BlacklistEnabled,
			WhitelistEnabled: ruleReq.WhitelistEnabled,
		}
		if err := accessController.AddNewAccessRule(newRule); err != nil {
			utils.SendErrorResponse(w, "failed to create access rule: "+err.Error())
			return
		}
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "id": ruleID})
}

// deleteAccessRule deletes an access rule
func (r *APIv1Router) deleteAccessRule(w http.ResponseWriter, req *http.Request, ruleID string) {
	if ruleID == "default" {
		http.Error(w, `{"error":"default access rule cannot be deleted"}`, http.StatusBadRequest)
		return
	}

	if err := accessController.RemoveAccessRuleByID(ruleID); err != nil {
		utils.SendErrorResponse(w, "failed to delete access rule: "+err.Error())
		return
	}

	// Broadcast to cluster
	if clusterManager != nil {
		clusterManager.BroadcastAccessRuleDelete(req.Context(), ruleID)
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "deleted": ruleID})
}

// ==================== Redirects REST API ====================

// registerRedirectRoutes registers redirect rule CRUD endpoints
func (r *APIv1Router) registerRedirectRoutes() {
	r.mux.HandleFunc("/api/v1/redirects", r.handleRedirects)
	r.mux.HandleFunc("/api/v1/redirects/", r.handleRedirectByURL)
}

// handleRedirects handles /api/v1/redirects
func (r *APIv1Router) handleRedirects(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		r.middleware.RequireScope(apitoken.ScopeRedirectRead, r.listRedirects)(w, req)
	case http.MethodPost:
		r.middleware.RequireScope(apitoken.ScopeRedirectWrite, r.createRedirect)(w, req)
	default:
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

// listRedirects returns all redirect rules
func (r *APIv1Router) listRedirects(w http.ResponseWriter, req *http.Request) {
	rules := redirectTable.GetAllRedirectRules()
	json.NewEncoder(w).Encode(rules)
}

// RedirectCreateRequest is the request body for creating/updating a redirect
type RedirectCreateRequest struct {
	RedirectURL       string `json:"redirectUrl"`
	TargetURL         string `json:"targetUrl"`
	ForwardChildpath  bool   `json:"forwardChildpath"`
	StatusCode        int    `json:"statusCode"`
	RequireExactMatch bool   `json:"requireExactMatch"`
}

// createRedirect creates a new redirect rule
func (r *APIv1Router) createRedirect(w http.ResponseWriter, req *http.Request) {
	var redirReq RedirectCreateRequest
	if err := json.NewDecoder(req.Body).Decode(&redirReq); err != nil {
		utils.SendErrorResponse(w, "invalid request body: "+err.Error())
		return
	}

	if redirReq.RedirectURL == "" || redirReq.TargetURL == "" {
		utils.SendErrorResponse(w, "redirectUrl and targetUrl are required")
		return
	}

	if redirReq.StatusCode == 0 {
		redirReq.StatusCode = 307
	}

	if err := redirectTable.AddRedirectRule(redirReq.RedirectURL, redirReq.TargetURL,
		redirReq.ForwardChildpath, redirReq.StatusCode, redirReq.RequireExactMatch); err != nil {
		utils.SendErrorResponse(w, "failed to create redirect: "+err.Error())
		return
	}

	// Broadcast to cluster
	if clusterManager != nil {
		clusterManager.BroadcastRedirectUpsert(req.Context(), redirReq.RedirectURL, redirReq.TargetURL,
			redirReq.ForwardChildpath, redirReq.StatusCode, redirReq.RequireExactMatch)
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "redirectUrl": redirReq.RedirectURL})
}

// handleRedirectByURL handles single redirect operations
func (r *APIv1Router) handleRedirectByURL(w http.ResponseWriter, req *http.Request) {
	// URL-decode the path after /api/v1/redirects/
	redirectURL := strings.TrimPrefix(req.URL.Path, "/api/v1/redirects/")
	if redirectURL == "" {
		http.Error(w, `{"error":"redirect URL required"}`, http.StatusBadRequest)
		return
	}

	switch req.Method {
	case http.MethodPut:
		r.middleware.RequireScope(apitoken.ScopeRedirectWrite, func(w http.ResponseWriter, req *http.Request) {
			r.updateRedirect(w, req, redirectURL)
		})(w, req)
	case http.MethodDelete:
		r.middleware.RequireScope(apitoken.ScopeRedirectWrite, func(w http.ResponseWriter, req *http.Request) {
			r.deleteRedirect(w, req, redirectURL)
		})(w, req)
	default:
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

// updateRedirect updates an existing redirect rule
func (r *APIv1Router) updateRedirect(w http.ResponseWriter, req *http.Request, redirectURL string) {
	var redirReq RedirectCreateRequest
	if err := json.NewDecoder(req.Body).Decode(&redirReq); err != nil {
		utils.SendErrorResponse(w, "invalid request body: "+err.Error())
		return
	}

	if redirReq.TargetURL == "" {
		utils.SendErrorResponse(w, "targetUrl is required")
		return
	}

	if redirReq.StatusCode == 0 {
		redirReq.StatusCode = 307
	}

	newRedirectURL := redirReq.RedirectURL
	if newRedirectURL == "" {
		newRedirectURL = redirectURL
	}

	if err := redirectTable.EditRedirectRule(redirectURL, newRedirectURL, redirReq.TargetURL,
		redirReq.ForwardChildpath, redirReq.StatusCode, redirReq.RequireExactMatch); err != nil {
		utils.SendErrorResponse(w, "failed to update redirect: "+err.Error())
		return
	}

	// Broadcast to cluster
	if clusterManager != nil {
		clusterManager.BroadcastRedirectUpsert(req.Context(), newRedirectURL, redirReq.TargetURL,
			redirReq.ForwardChildpath, redirReq.StatusCode, redirReq.RequireExactMatch)
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "redirectUrl": newRedirectURL})
}

// deleteRedirect deletes a redirect rule
func (r *APIv1Router) deleteRedirect(w http.ResponseWriter, req *http.Request, redirectURL string) {
	if err := redirectTable.DeleteRedirectRule(redirectURL); err != nil {
		utils.SendErrorResponse(w, "failed to delete redirect: "+err.Error())
		return
	}

	// Broadcast to cluster
	if clusterManager != nil {
		clusterManager.BroadcastRedirectDelete(req.Context(), redirectURL)
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "deleted": redirectURL})
}

// ==================== Certificates REST API ====================

// registerCertRoutes registers certificate CRUD endpoints
func (r *APIv1Router) registerCertRoutes() {
	r.mux.HandleFunc("/api/v1/certs", r.middleware.RequireScope(apitoken.ScopeCertRead, r.handleCerts))
	r.mux.HandleFunc("/api/v1/certs/", r.handleCertByDomain)
}

// handleCerts handles GET /api/v1/certs - list all certificates
func (r *APIv1Router) handleCerts(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	domains, err := tlsCertManager.ListCertDomains()
	if err != nil {
		utils.SendErrorResponse(w, "failed to list certificates: "+err.Error())
		return
	}

	type CertInfo struct {
		Domain string `json:"domain"`
	}

	certs := []CertInfo{}
	for _, domain := range domains {
		certs = append(certs, CertInfo{Domain: domain})
	}

	json.NewEncoder(w).Encode(certs)
}

// handleCertByDomain handles single certificate operations
func (r *APIv1Router) handleCertByDomain(w http.ResponseWriter, req *http.Request) {
	domain := strings.TrimPrefix(req.URL.Path, "/api/v1/certs/")
	if domain == "" {
		http.Error(w, `{"error":"domain required"}`, http.StatusBadRequest)
		return
	}

	switch req.Method {
	case http.MethodGet:
		r.middleware.RequireScope(apitoken.ScopeCertRead, func(w http.ResponseWriter, req *http.Request) {
			r.getCert(w, req, domain)
		})(w, req)
	case http.MethodDelete:
		r.middleware.RequireScope(apitoken.ScopeCertWrite, func(w http.ResponseWriter, req *http.Request) {
			r.deleteCert(w, req, domain)
		})(w, req)
	default:
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

// getCert retrieves certificate info for a domain
func (r *APIv1Router) getCert(w http.ResponseWriter, req *http.Request, domain string) {
	// Check if certificate exists
	domains, err := tlsCertManager.ListCertDomains()
	if err != nil {
		utils.SendErrorResponse(w, "failed to list certificates: "+err.Error())
		return
	}

	found := false
	for _, d := range domains {
		if d == domain {
			found = true
			break
		}
	}

	if !found {
		http.Error(w, `{"error":"certificate not found"}`, http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"domain": domain, "status": "exists"})
}

// deleteCert deletes a certificate
func (r *APIv1Router) deleteCert(w http.ResponseWriter, req *http.Request, domain string) {
	if err := tlsCertManager.RemoveCert(domain); err != nil {
		utils.SendErrorResponse(w, "failed to delete certificate: "+err.Error())
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "deleted": domain})
}

// registerClusterRoutes registers cluster management endpoints
func (r *APIv1Router) registerClusterRoutes() {
	// Cluster status (read-only)
	r.mux.HandleFunc("/api/v1/cluster/status", r.middleware.RequireScope(apitoken.ScopeClusterRead, r.handleClusterStatus))
	// Cluster config (read/write based on method)
	r.mux.HandleFunc("/api/v1/cluster/config", r.handleClusterConfigWithScope)
	// Cluster peers (read/write based on method)
	r.mux.HandleFunc("/api/v1/cluster/peers", r.handleClusterPeersWithScope)
}

// handleClusterConfigWithScope routes to the appropriate scope based on method
func (r *APIv1Router) handleClusterConfigWithScope(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		r.middleware.RequireScope(apitoken.ScopeClusterRead, r.handleClusterConfig)(w, req)
	case http.MethodPut, http.MethodPost:
		r.middleware.RequireScope(apitoken.ScopeClusterWrite, r.handleClusterConfig)(w, req)
	default:
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

// handleClusterPeersWithScope routes to the appropriate scope based on method
func (r *APIv1Router) handleClusterPeersWithScope(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		r.middleware.RequireScope(apitoken.ScopeClusterRead, r.handleClusterPeers)(w, req)
	case http.MethodPost, http.MethodDelete:
		r.middleware.RequireScope(apitoken.ScopeClusterWrite, r.handleClusterPeers)(w, req)
	default:
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

// handleClusterStatus returns the current cluster status
func (r *APIv1Router) handleClusterStatus(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	if clusterManager == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"enabled": false,
			"message": "Cluster manager not initialized",
		})
		return
	}

	status := clusterManager.Status()
	json.NewEncoder(w).Encode(status)
}

// handleClusterConfig handles GET/PUT for cluster configuration
func (r *APIv1Router) handleClusterConfig(w http.ResponseWriter, req *http.Request) {
	if clusterManager == nil {
		http.Error(w, `{"error":"cluster manager not initialized"}`, http.StatusServiceUnavailable)
		return
	}

	switch req.Method {
	case http.MethodGet:
		cfg := clusterManager.GetConfig()
		// Mask the shared secret for security
		if cfg.SharedSecret != "" {
			cfg.SharedSecret = "********"
		}
		json.NewEncoder(w).Encode(cfg)

	case http.MethodPut:
		var newCfg ClusterConfig
		if err := json.NewDecoder(req.Body).Decode(&newCfg); err != nil {
			http.Error(w, `{"error":"invalid JSON body"}`, http.StatusBadRequest)
			return
		}

		// If shared secret is masked, keep the existing one
		if newCfg.SharedSecret == "********" {
			existingCfg := clusterManager.GetConfig()
			newCfg.SharedSecret = existingCfg.SharedSecret
		}

		if err := clusterManager.UpdateConfig(newCfg); err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})

	default:
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

// handleClusterPeers handles peer management
func (r *APIv1Router) handleClusterPeers(w http.ResponseWriter, req *http.Request) {
	if clusterManager == nil {
		http.Error(w, `{"error":"cluster manager not initialized"}`, http.StatusServiceUnavailable)
		return
	}

	switch req.Method {
	case http.MethodGet:
		cfg := clusterManager.GetConfig()
		json.NewEncoder(w).Encode(cfg.Peers)

	case http.MethodPost:
		// Add a new peer
		var peer ClusterPeer
		if err := json.NewDecoder(req.Body).Decode(&peer); err != nil {
			http.Error(w, `{"error":"invalid JSON body"}`, http.StatusBadRequest)
			return
		}

		if peer.BaseURL == "" {
			http.Error(w, `{"error":"baseUrl is required"}`, http.StatusBadRequest)
			return
		}

		cfg := clusterManager.GetConfig()
		// Check for duplicate
		for _, p := range cfg.Peers {
			if p.BaseURL == peer.BaseURL {
				http.Error(w, `{"error":"peer already exists"}`, http.StatusConflict)
				return
			}
		}

		cfg.Peers = append(cfg.Peers, peer)
		if err := clusterManager.UpdateConfig(cfg); err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(peer)

	case http.MethodDelete:
		// Delete a peer by baseUrl
		baseURL := req.URL.Query().Get("baseUrl")
		if baseURL == "" {
			http.Error(w, `{"error":"baseUrl query parameter is required"}`, http.StatusBadRequest)
			return
		}

		cfg := clusterManager.GetConfig()
		found := false
		newPeers := make([]ClusterPeer, 0, len(cfg.Peers))
		for _, p := range cfg.Peers {
			if p.BaseURL == baseURL {
				found = true
			} else {
				newPeers = append(newPeers, p)
			}
		}

		if !found {
			http.Error(w, `{"error":"peer not found"}`, http.StatusNotFound)
			return
		}

		cfg.Peers = newPeers
		if err := clusterManager.UpdateConfig(cfg); err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "deleted": baseURL})

	default:
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}
