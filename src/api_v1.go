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
	router.registerProxyRoutes()
	router.registerVdirRoutes()

	return router
}

// ServeHTTP implements http.Handler
func (r *APIv1Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// Set JSON content type for all API responses
	w.Header().Set("Content-Type", "application/json")
	r.mux.ServeHTTP(w, req)
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

