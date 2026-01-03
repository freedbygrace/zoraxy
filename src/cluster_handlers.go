package main

import (
    "crypto/rand"
    "encoding/base64"
    "encoding/json"
    "errors"
    "net"
    "net/http"
    "os"
    "path/filepath"
    "strconv"
    "strings"
    "time"

    "imuslab.com/zoraxy/mod/access"
    "imuslab.com/zoraxy/mod/dynamicproxy"
    "imuslab.com/zoraxy/mod/utils"
)

// getRequestSourceIP extracts the source IP from an incoming request
func getRequestSourceIP(r *http.Request) string {
    // Check X-Forwarded-For header first
    if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
        ips := strings.Split(xff, ",")
        if len(ips) > 0 {
            return strings.TrimSpace(ips[0])
        }
    }
    // Check X-Real-IP header
    if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
        return realIP
    }
    // Fall back to RemoteAddr
    host, _, err := net.SplitHostPort(r.RemoteAddr)
    if err != nil {
        return r.RemoteAddr
    }
    return host
}

// Admin API: get or update cluster configuration
func HandleClusterConfig(w http.ResponseWriter, r *http.Request) {
    if clusterManager == nil {
        SystemWideLogger.PrintAndLog("cluster", "Cluster config request failed: cluster manager not initialized", nil)
        utils.SendErrorResponse(w, "cluster manager not initialized")
        return
    }

    switch r.Method {
    case http.MethodGet:
        cfg := clusterManager.GetConfig()
        js, err := json.Marshal(cfg)
        if err != nil {
            SystemWideLogger.PrintAndLog("cluster", "Failed to marshal cluster config", err)
            utils.SendErrorResponse(w, "failed to marshal config: "+err.Error())
            return
        }
        utils.SendJSONResponse(w, string(js))
    case http.MethodPost:
        SystemWideLogger.PrintAndLog("cluster", "Received cluster config update request", nil)
        var cfg ClusterConfig
        if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
            SystemWideLogger.PrintAndLog("cluster", "Invalid JSON in cluster config request", err)
            utils.SendErrorResponse(w, "invalid json: "+err.Error())
            return
        }
        if cfg.Enabled && cfg.SharedSecret == "" {
            SystemWideLogger.PrintAndLog("cluster", "Cluster config rejected: missing shared secret", nil)
            utils.SendErrorResponse(w, "sharedSecret is required when cluster is enabled")
            return
        }
        SystemWideLogger.PrintAndLog("cluster", "Updating cluster config: enabled="+boolToStr(cfg.Enabled)+", meshMode="+boolToStr(cfg.MeshMode)+", advertiseAddr="+cfg.AdvertiseAddr+", swarmEnabled="+boolToStr(cfg.SwarmEnabled)+", swarmService="+cfg.SwarmService, nil)
        if err := clusterManager.UpdateConfig(cfg); err != nil {
            SystemWideLogger.PrintAndLog("cluster", "Failed to save cluster config", err)
            utils.SendErrorResponse(w, "failed to save config: "+err.Error())
            return
        }
        SystemWideLogger.PrintAndLog("cluster", "Cluster configuration saved successfully", nil)
        utils.SendOK(w)
    default:
        http.Error(w, "405 - Method not allowed", http.StatusMethodNotAllowed)
    }
}

// boolToStr converts a bool to "true" or "false" string for logging
func boolToStr(b bool) string {
    if b {
        return "true"
    }
    return "false"
}

// Admin API: report cluster status
func HandleClusterStatus(w http.ResponseWriter, r *http.Request) {
    if clusterManager == nil {
        utils.SendErrorResponse(w, "cluster manager not initialized")
        return
    }
    status := clusterManager.Status()
    js, err := json.Marshal(status)
    if err != nil {
        utils.SendErrorResponse(w, "failed to marshal status: "+err.Error())
        return
    }
    utils.SendJSONResponse(w, string(js))
}

// Internal helper: apply an incoming proxy endpoint from cluster peer to runtime
func applyClusterProxyEndpoint(ep *dynamicproxy.ProxyEndpoint) error {
    if ep == nil {
        return errors.New("nil endpoint")
    }

    switch ep.ProxyType {
    case dynamicproxy.ProxyTypeRoot:
        prepared, err := dynamicProxyRouter.PrepareProxyRoute(ep)
        if err != nil {
            return err
        }
        return dynamicProxyRouter.SetProxyRouteAsRoot(prepared)
    case dynamicproxy.ProxyTypeHost:
        prepared, err := dynamicProxyRouter.PrepareProxyRoute(ep)
        if err != nil {
            return err
        }
        return dynamicProxyRouter.AddProxyRouteToRuntime(prepared)
    default:
        return errors.New("unsupported proxy type")
    }
}

// Inter-node API: upsert (create/update) a proxy endpoint
func HandleClusterProxyUpsert(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "405 - Method not allowed", http.StatusMethodNotAllowed)
        return
    }
    if clusterManager == nil || !clusterManager.IsEnabled() {
        http.Error(w, "503 - Cluster disabled", http.StatusServiceUnavailable)
        return
    }
    if !clusterManager.CheckSharedSecret(r.Header.Get("X-Zoraxy-Cluster-Secret")) {
        http.Error(w, "401 - Unauthorized", http.StatusUnauthorized)
        return
    }

    var req ProxyUpsertRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        utils.SendErrorResponse(w, "invalid json: "+err.Error())
        return
    }

    if req.Endpoint == nil {
        utils.SendErrorResponse(w, "missing endpoint")
        return
    }

    if req.Endpoint.RootOrMatchingDomain == "" {
        req.Endpoint.RootOrMatchingDomain = "/"
    }

    // Ignore our own changes (a peer might be misconfigured and point to itself)
    if req.OriginNodeID == nodeUUID {
        utils.SendOK(w)
        return
    }

    key := req.Endpoint.RootOrMatchingDomain
    if !clusterManager.ShouldApplyProxyUpdate(key, req.Timestamp) {
        // Outdated update, safe to ignore
        if SystemWideLogger != nil {
            SystemWideLogger.PrintAndLog("cluster", "Skipping outdated proxy upsert for: "+key+" (timestamp check)", nil)
        }
        utils.SendOK(w)
        return
    }

    if err := applyClusterProxyEndpoint(req.Endpoint); err != nil {
        utils.SendErrorResponse(w, "failed to apply endpoint: "+err.Error())
        return
    }

    if err := SaveReverseProxyConfig(req.Endpoint); err != nil {
        utils.SendErrorResponse(w, "failed to save config: "+err.Error())
        return
    }

    // Record this node as a sync source
    clusterManager.RecordSyncSource(req.OriginNodeID, getRequestSourceIP(r), "proxy")

    // Mesh mode: auto-add peer if not already known
    clusterManager.AutoAddPeerFromRequest(r, req.OriginNodeID)

    if SystemWideLogger != nil {
        SystemWideLogger.PrintAndLog("cluster", "Received proxy upsert from peer: "+req.Endpoint.RootOrMatchingDomain+" (node: "+req.OriginNodeID+")", nil)
    }

    UpdateUptimeMonitorTargets()
    utils.SendOK(w)
}

// Inter-node API: delete a proxy endpoint
func HandleClusterProxyDelete(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "405 - Method not allowed", http.StatusMethodNotAllowed)
        return
    }
    if clusterManager == nil || !clusterManager.IsEnabled() {
        http.Error(w, "503 - Cluster disabled", http.StatusServiceUnavailable)
        return
    }
    if !clusterManager.CheckSharedSecret(r.Header.Get("X-Zoraxy-Cluster-Secret")) {
        http.Error(w, "401 - Unauthorized", http.StatusUnauthorized)
        return
    }

    var req ProxyDeleteRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        utils.SendErrorResponse(w, "invalid json: "+err.Error())
        return
    }

    if req.RootOrMatchingDomain == "" {
        utils.SendErrorResponse(w, "missing endpoint id")
        return
    }

    if req.OriginNodeID == nodeUUID {
        utils.SendOK(w)
        return
    }

    key := req.RootOrMatchingDomain
    if !clusterManager.ShouldApplyProxyUpdate(key, req.Timestamp) {
        utils.SendOK(w)
        return
    }

    if err := dynamicProxyRouter.RemoveProxyEndpointByRootname(key); err != nil {
        // If the endpoint does not exist in runtime it is safe to ignore
        if err.Error() != "target routing rule not found" {
            utils.SendErrorResponse(w, "failed to remove endpoint: "+err.Error())
            return
        }
    }

    if err := RemoveReverseProxyConfig(key); err != nil {
        // Ignore missing config files
        if !errors.Is(err, os.ErrNotExist) {
            utils.SendErrorResponse(w, "failed to remove config file: "+err.Error())
            return
        }
    }

    // Record this node as a sync source
    clusterManager.RecordSyncSource(req.OriginNodeID, getRequestSourceIP(r), "proxy-delete")

    // Mesh mode: auto-add peer if not already known
    clusterManager.AutoAddPeerFromRequest(r, req.OriginNodeID)

    if SystemWideLogger != nil {
        SystemWideLogger.PrintAndLog("cluster", "Received proxy delete from peer: "+req.RootOrMatchingDomain+" (node: "+req.OriginNodeID+")", nil)
    }

    UpdateUptimeMonitorTargets()
    utils.SendOK(w)
}

// Admin API: generate a cryptographically secure random secret
func HandleClusterGenerateSecret(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "405 - Method not allowed", http.StatusMethodNotAllowed)
        return
    }
    // Generate 32 bytes (256 bits) of random data
    bytes := make([]byte, 32)
    if _, err := rand.Read(bytes); err != nil {
        utils.SendErrorResponse(w, "failed to generate random bytes: "+err.Error())
        return
    }
    // Encode as URL-safe base64
    secret := base64.URLEncoding.EncodeToString(bytes)
    utils.SendTextResponse(w, secret)
}

// Admin API: auto-detect the advertise address for mesh mode
func HandleClusterDetectAdvertiseAddr(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "405 - Method not allowed", http.StatusMethodNotAllowed)
        return
    }
    if clusterManager == nil {
        utils.SendErrorResponse(w, "cluster manager not initialized")
        return
    }

    // Determine the management port from the webUIPort flag
    mgmtPort := 8000
    if webUIPort != nil {
        portStr := strings.TrimPrefix(*webUIPort, ":")
        if p, err := strconv.Atoi(portStr); err == nil {
            mgmtPort = p
        }
    }

    // Check for environment variable first
    if envAddr := os.Getenv("ZORAXY_ADVERTISE_ADDR"); envAddr != "" {
        result := map[string]string{
            "address": envAddr,
            "source":  "environment",
        }
        js, _ := json.Marshal(result)
        utils.SendJSONResponse(w, string(js))
        return
    }

    // Use the auto-detect function
    detectedAddr := clusterManager.AutoDetectAdvertiseAddr(mgmtPort)
    if detectedAddr == "" {
        utils.SendErrorResponse(w, "could not detect suitable IP address")
        return
    }

    result := map[string]string{
        "address": detectedAddr,
        "source":  "auto-detect",
    }
    js, _ := json.Marshal(result)
    utils.SendJSONResponse(w, string(js))
}

// Inter-node API: receive a certificate sync from a peer
// Protected by shared secret, not web auth
func HandleClusterCertSync(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "405 - Method not allowed", http.StatusMethodNotAllowed)
        return
    }
    if clusterManager == nil || !clusterManager.IsEnabled() {
        utils.SendErrorResponse(w, "cluster not enabled")
        return
    }

    // Verify shared secret
    secret := r.Header.Get("X-Zoraxy-Cluster-Secret")
    if !clusterManager.CheckSharedSecret(secret) {
        http.Error(w, "403 - Forbidden", http.StatusForbidden)
        return
    }

    var payload CertSyncPayload
    if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
        utils.SendErrorResponse(w, "invalid json: "+err.Error())
        return
    }

    // Validate payload
    if payload.Domain == "" {
        utils.SendErrorResponse(w, "domain is required")
        return
    }
    if len(payload.PubKeyPEM) == 0 || len(payload.PrivKeyPEM) == 0 {
        utils.SendErrorResponse(w, "certificate data is required")
        return
    }

    // Sanitize domain to prevent path traversal
    domain := filepath.Base(payload.Domain)
    domain = strings.TrimSuffix(domain, ".pem")
    domain = strings.TrimSuffix(domain, ".key")
    if domain == "" || domain == "." || domain == ".." {
        utils.SendErrorResponse(w, "invalid domain")
        return
    }

    // Check if we should apply this update (timestamp-based)
    if !clusterManager.ShouldApplyCertUpdate(domain, payload.Timestamp) {
        // We already have a newer version, skip
        utils.SendOK(w)
        return
    }

    // Write certificate files
    pubKeyPath := filepath.Join(CONF_CERT_STORE, domain+".pem")
    privKeyPath := filepath.Join(CONF_CERT_STORE, domain+".key")

    // Ensure cert store exists
    if err := os.MkdirAll(CONF_CERT_STORE, 0775); err != nil {
        utils.SendErrorResponse(w, "failed to create cert store: "+err.Error())
        return
    }

    // Write public key
    if err := os.WriteFile(pubKeyPath, payload.PubKeyPEM, 0644); err != nil {
        utils.SendErrorResponse(w, "failed to write public key: "+err.Error())
        return
    }

    // Write private key
    if err := os.WriteFile(privKeyPath, payload.PrivKeyPEM, 0600); err != nil {
        utils.SendErrorResponse(w, "failed to write private key: "+err.Error())
        return
    }

    // Reload certificate list in the TLS manager
    if tlsCertManager != nil {
        tlsCertManager.UpdateLoadedCertList()
    }

    // Record this node as a sync source
    clusterManager.RecordSyncSource(payload.OriginNodeID, getRequestSourceIP(r), "cert")

    // Mesh mode: auto-add peer if not already known
    clusterManager.AutoAddPeerFromRequest(r, payload.OriginNodeID)

    if SystemWideLogger != nil {
        SystemWideLogger.PrintAndLog("cluster", "Received certificate sync for domain: "+domain+" from node: "+payload.OriginNodeID, nil)
    }

    utils.SendOK(w)
}

// Inter-node API: list certificates with timestamps for full sync
// Protected by shared secret, not web auth
func HandleClusterCertList(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "405 - Method not allowed", http.StatusMethodNotAllowed)
        return
    }
    if clusterManager == nil || !clusterManager.IsEnabled() {
        utils.SendErrorResponse(w, "cluster not enabled")
        return
    }

    // Verify shared secret
    secret := r.Header.Get("X-Zoraxy-Cluster-Secret")
    if !clusterManager.CheckSharedSecret(secret) {
        http.Error(w, "403 - Forbidden", http.StatusForbidden)
        return
    }

    // List certificates
    type CertInfo struct {
        Domain   string `json:"domain"`
        ModTime  int64  `json:"modTime"`
        HasKey   bool   `json:"hasKey"`
        HasCert  bool   `json:"hasCert"`
    }

    certs := []CertInfo{}

    files, err := os.ReadDir(CONF_CERT_STORE)
    if err != nil {
        if os.IsNotExist(err) {
            // No certs directory yet
            js, _ := json.Marshal(certs)
            utils.SendJSONResponse(w, string(js))
            return
        }
        utils.SendErrorResponse(w, "failed to read cert store: "+err.Error())
        return
    }

    // Build map of domains
    domainMap := make(map[string]*CertInfo)
    for _, f := range files {
        if f.IsDir() {
            continue
        }
        name := f.Name()
        var domain string
        var isCert, isKey bool

        if strings.HasSuffix(name, ".pem") {
            domain = strings.TrimSuffix(name, ".pem")
            isCert = true
        } else if strings.HasSuffix(name, ".key") {
            domain = strings.TrimSuffix(name, ".key")
            isKey = true
        } else {
            continue
        }

        info, err := f.Info()
        if err != nil {
            continue
        }

        if existing, ok := domainMap[domain]; ok {
            if isCert {
                existing.HasCert = true
            }
            if isKey {
                existing.HasKey = true
            }
            // Use newer mod time
            if info.ModTime().Unix() > existing.ModTime {
                existing.ModTime = info.ModTime().Unix()
            }
        } else {
            domainMap[domain] = &CertInfo{
                Domain:  domain,
                ModTime: info.ModTime().Unix(),
                HasCert: isCert,
                HasKey:  isKey,
            }
        }
    }

    for _, ci := range domainMap {
        if ci.HasCert && ci.HasKey {
            certs = append(certs, *ci)
        }
    }

    js, err := json.Marshal(certs)
    if err != nil {
        utils.SendErrorResponse(w, "failed to marshal cert list: "+err.Error())
        return
    }
    utils.SendJSONResponse(w, string(js))
}

// HandleClusterAccessRuleSync receives access rule sync from peers
func HandleClusterAccessRuleSync(w http.ResponseWriter, r *http.Request) {
    if clusterManager == nil || accessController == nil {
        utils.SendErrorResponse(w, "cluster or access controller not initialized")
        return
    }

    if !clusterManager.IsSyncAccessRulesEnabled() {
        utils.SendErrorResponse(w, "access rule sync disabled")
        return
    }

    if !clusterManager.ValidateClusterRequest(r) {
        utils.SendErrorResponse(w, "unauthorized")
        return
    }

    var payload AccessRuleSyncPayload
    if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
        utils.SendErrorResponse(w, "invalid payload: "+err.Error())
        return
    }

    if payload.ID == "" {
        utils.SendErrorResponse(w, "missing access rule ID")
        return
    }

    // Check if we already have a newer version
    if !clusterManager.ShouldAcceptAccessRuleUpdate(payload.ID, payload.Timestamp) {
        utils.SendOK(w)
        return
    }

    // Record the timestamp
    clusterManager.RecordAccessRuleTimestamp(payload.ID, payload.Timestamp)

    // Create or update the access rule
    whiteListCC := payload.WhiteListCountryCode
    whiteListIP := payload.WhiteListIP
    blackListCC := payload.BlackListCountryCode
    blackListIP := payload.BlackListIP

    newRule := &access.AccessRule{
        ID:                             payload.ID,
        Name:                           payload.Name,
        Desc:                           payload.Desc,
        BlacklistEnabled:               payload.BlacklistEnabled,
        WhitelistEnabled:               payload.WhitelistEnabled,
        WhitelistAllowLocalAndLoopback: payload.WhitelistAllowLocal,
        WhiteListCountryCode:           &whiteListCC,
        WhiteListIP:                    &whiteListIP,
        BlackListContryCode:            &blackListCC,
        BlackListIP:                    &blackListIP,
    }

    // Check if rule exists
    existingRule, err := accessController.GetAccessRuleByID(payload.ID)
    if err != nil {
        // Rule doesn't exist, add it
        err = accessController.AddNewAccessRule(newRule)
        if err != nil {
            utils.SendErrorResponse(w, "failed to add access rule: "+err.Error())
            return
        }
    } else {
        // Update existing rule
        existingRule.Name = newRule.Name
        existingRule.Desc = newRule.Desc
        existingRule.BlacklistEnabled = newRule.BlacklistEnabled
        existingRule.WhitelistEnabled = newRule.WhitelistEnabled
        existingRule.WhitelistAllowLocalAndLoopback = newRule.WhitelistAllowLocalAndLoopback
        existingRule.WhiteListCountryCode = newRule.WhiteListCountryCode
        existingRule.WhiteListIP = newRule.WhiteListIP
        existingRule.BlackListContryCode = newRule.BlackListContryCode
        existingRule.BlackListIP = newRule.BlackListIP
        existingRule.SaveChanges()
    }

    // Record this node as a sync source
    clusterManager.RecordSyncSource(payload.OriginNodeID, getRequestSourceIP(r), "accessRule")

    // Mesh mode: auto-add peer if not already known
    clusterManager.AutoAddPeerFromRequest(r, payload.OriginNodeID)

    SystemWideLogger.PrintAndLog("cluster", "Synced access rule from peer: "+payload.ID, nil)
    utils.SendOK(w)
}

// HandleClusterAccessRuleDelete receives access rule deletion from peers
func HandleClusterAccessRuleDelete(w http.ResponseWriter, r *http.Request) {
    if clusterManager == nil || accessController == nil {
        utils.SendErrorResponse(w, "cluster or access controller not initialized")
        return
    }

    if !clusterManager.IsSyncAccessRulesEnabled() {
        utils.SendErrorResponse(w, "access rule sync disabled")
        return
    }

    if !clusterManager.ValidateClusterRequest(r) {
        utils.SendErrorResponse(w, "unauthorized")
        return
    }

    var payload struct {
        OriginNodeID string `json:"originNodeId"`
        Timestamp    int64  `json:"timestamp"`
        ID           string `json:"id"`
    }
    if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
        utils.SendErrorResponse(w, "invalid payload: "+err.Error())
        return
    }

    if payload.ID == "" || payload.ID == "default" {
        utils.SendErrorResponse(w, "invalid access rule ID")
        return
    }

    // Delete the access rule
    err := accessController.DeleteAccessRuleByID(payload.ID)
    if err != nil {
        // Rule might not exist, that's OK
        SystemWideLogger.PrintAndLog("cluster", "Access rule delete sync (may not exist): "+payload.ID, nil)
    } else {
        SystemWideLogger.PrintAndLog("cluster", "Deleted access rule from peer sync: "+payload.ID, nil)
    }

    // Record this node as a sync source
    clusterManager.RecordSyncSource(payload.OriginNodeID, getRequestSourceIP(r), "accessRule-delete")

    // Mesh mode: auto-add peer if not already known
    clusterManager.AutoAddPeerFromRequest(r, payload.OriginNodeID)

    utils.SendOK(w)
}

// HandleClusterRedirectSync receives redirect rule sync from peers
func HandleClusterRedirectSync(w http.ResponseWriter, r *http.Request) {
    if clusterManager == nil || redirectTable == nil {
        utils.SendErrorResponse(w, "cluster or redirect table not initialized")
        return
    }

    if !clusterManager.IsSyncRedirectsEnabled() {
        utils.SendErrorResponse(w, "redirect sync disabled")
        return
    }

    if !clusterManager.ValidateClusterRequest(r) {
        utils.SendErrorResponse(w, "unauthorized")
        return
    }

    var payload RedirectSyncPayload
    if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
        utils.SendErrorResponse(w, "invalid payload: "+err.Error())
        return
    }

    if payload.RedirectURL == "" {
        utils.SendErrorResponse(w, "missing redirect URL")
        return
    }

    // Delete existing rule if any, then add the new one
    redirectTable.DeleteRedirectRule(payload.RedirectURL)
    err := redirectTable.AddRedirectRule(payload.RedirectURL, payload.TargetURL, payload.ForwardChildpath, payload.StatusCode, payload.RequireExactMatch)
    if err != nil {
        utils.SendErrorResponse(w, "failed to add redirect rule: "+err.Error())
        return
    }

    // Record this node as a sync source
    clusterManager.RecordSyncSource(payload.OriginNodeID, getRequestSourceIP(r), "redirect")

    // Mesh mode: auto-add peer if not already known
    clusterManager.AutoAddPeerFromRequest(r, payload.OriginNodeID)

    SystemWideLogger.PrintAndLog("cluster", "Synced redirect rule from peer: "+payload.RedirectURL, nil)
    utils.SendOK(w)
}

// HandleClusterRedirectDelete receives redirect rule deletion from peers
func HandleClusterRedirectDelete(w http.ResponseWriter, r *http.Request) {
    if clusterManager == nil || redirectTable == nil {
        utils.SendErrorResponse(w, "cluster or redirect table not initialized")
        return
    }

    if !clusterManager.IsSyncRedirectsEnabled() {
        utils.SendErrorResponse(w, "redirect sync disabled")
        return
    }

    if !clusterManager.ValidateClusterRequest(r) {
        utils.SendErrorResponse(w, "unauthorized")
        return
    }

    var payload struct {
        OriginNodeID string `json:"originNodeId"`
        Timestamp    int64  `json:"timestamp"`
        RedirectURL  string `json:"redirectUrl"`
    }
    if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
        utils.SendErrorResponse(w, "invalid payload: "+err.Error())
        return
    }

    if payload.RedirectURL == "" {
        utils.SendErrorResponse(w, "missing redirect URL")
        return
    }

    err := redirectTable.DeleteRedirectRule(payload.RedirectURL)
    if err != nil {
        SystemWideLogger.PrintAndLog("cluster", "Redirect delete sync error: "+err.Error(), nil)
    } else {
        SystemWideLogger.PrintAndLog("cluster", "Deleted redirect rule from peer sync: "+payload.RedirectURL, nil)
    }

    // Record this node as a sync source
    clusterManager.RecordSyncSource(payload.OriginNodeID, getRequestSourceIP(r), "redirect-delete")

    // Mesh mode: auto-add peer if not already known
    clusterManager.AutoAddPeerFromRequest(r, payload.OriginNodeID)

    utils.SendOK(w)
}

// HandleClusterAPITokenSync receives API token sync from peers
func HandleClusterAPITokenSync(w http.ResponseWriter, r *http.Request) {
    if clusterManager == nil || apiTokenManager == nil {
        utils.SendErrorResponse(w, "cluster or API token manager not initialized")
        return
    }

    if !clusterManager.IsSyncAPITokensEnabled() {
        utils.SendErrorResponse(w, "API token sync disabled")
        return
    }

    if !clusterManager.ValidateClusterRequest(r) {
        utils.SendErrorResponse(w, "unauthorized")
        return
    }

    var payload APITokenSyncPayload
    if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
        utils.SendErrorResponse(w, "invalid payload: "+err.Error())
        return
    }

    if payload.TokenID == "" {
        utils.SendErrorResponse(w, "missing token ID")
        return
    }

    // Decode the scopes JSON
    var scopes []string
    if payload.Scopes != "" {
        if err := json.Unmarshal([]byte(payload.Scopes), &scopes); err != nil {
            utils.SendErrorResponse(w, "invalid scopes JSON: "+err.Error())
            return
        }
    }

    // Import the token using the hash (already hashed from origin)
    err := apiTokenManager.ImportTokenFromCluster(
        payload.TokenID,
        payload.Name,
        payload.TokenHash,
        scopes,
        time.Unix(payload.CreatedAt, 0),
        time.Unix(payload.ExpiresAt, 0),
        payload.Description,
        payload.Disabled,
    )
    if err != nil {
        utils.SendErrorResponse(w, "failed to import token: "+err.Error())
        return
    }

    // Record this node as a sync source
    clusterManager.RecordSyncSource(payload.OriginNodeID, getRequestSourceIP(r), "apiToken")

    // Mesh mode: auto-add peer if not already known
    clusterManager.AutoAddPeerFromRequest(r, payload.OriginNodeID)

    SystemWideLogger.PrintAndLog("cluster", "Synced API token from peer: "+payload.Name, nil)
    utils.SendOK(w)
}

// HandleClusterAPITokenDelete receives API token deletion from peers
func HandleClusterAPITokenDelete(w http.ResponseWriter, r *http.Request) {
    if clusterManager == nil || apiTokenManager == nil {
        utils.SendErrorResponse(w, "cluster or API token manager not initialized")
        return
    }

    if !clusterManager.IsSyncAPITokensEnabled() {
        utils.SendErrorResponse(w, "API token sync disabled")
        return
    }

    if !clusterManager.ValidateClusterRequest(r) {
        utils.SendErrorResponse(w, "unauthorized")
        return
    }

    var payload APITokenDeletePayload
    if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
        utils.SendErrorResponse(w, "invalid payload: "+err.Error())
        return
    }

    if payload.TokenID == "" {
        utils.SendErrorResponse(w, "missing token ID")
        return
    }

    // Delete the token
    err := apiTokenManager.DeleteToken(payload.TokenID)
    if err != nil {
        // Token might not exist, that's OK
        SystemWideLogger.PrintAndLog("cluster", "API token delete sync (may not exist): "+payload.TokenID, nil)
    } else {
        SystemWideLogger.PrintAndLog("cluster", "Deleted API token from peer sync: "+payload.TokenID, nil)
    }

    // Record this node as a sync source
    clusterManager.RecordSyncSource(payload.OriginNodeID, getRequestSourceIP(r), "apiToken-delete")

    // Mesh mode: auto-add peer if not already known
    clusterManager.AutoAddPeerFromRequest(r, payload.OriginNodeID)

    utils.SendOK(w)
}

// HandleClusterHeartbeat handles heartbeat requests from peer nodes
// This is used for health checking and peer discovery in mesh mode
func HandleClusterHeartbeat(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "405 - Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    if clusterManager == nil || !clusterManager.IsEnabled() {
        http.Error(w, "503 - Cluster disabled", http.StatusServiceUnavailable)
        return
    }

    // Verify shared secret
    if !clusterManager.CheckSharedSecret(r.Header.Get("X-Zoraxy-Cluster-Secret")) {
        http.Error(w, "401 - Unauthorized", http.StatusUnauthorized)
        return
    }

    var req HeartbeatRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        utils.SendErrorResponse(w, "invalid json: "+err.Error())
        return
    }

    // Ignore our own heartbeat
    if req.NodeID == nodeUUID {
        utils.SendOK(w)
        return
    }

    // Log heartbeat received
    if SystemWideLogger != nil {
        SystemWideLogger.PrintAndLog("cluster", "Heartbeat received from "+req.Hostname+" ("+req.NodeID[:8]+"...)", nil)
    }

    // Record this node as a sync source
    clusterManager.RecordSyncSource(req.NodeID, getRequestSourceIP(r), "heartbeat")

    // Mesh mode: auto-add peer if not already known
    if req.AdvertiseAddr != "" {
        r.Header.Set("X-Zoraxy-Advertise-URL", req.AdvertiseAddr)
        clusterManager.AutoAddPeerFromRequest(r, req.NodeID)
    }

    // Mesh mode: merge their known peers
    if clusterManager.IsMeshModeEnabled() && len(req.KnownPeers) > 0 {
        clusterManager.MergeKnownPeersPublic(req.KnownPeers)
    }

    // Build response with our info
    cfg := clusterManager.GetConfig()
    resp := HeartbeatResponse{
        NodeID:        nodeUUID,
        Hostname:      clusterManager.GetHostname(),
        AdvertiseAddr: cfg.AdvertiseAddr,
        Timestamp:     time.Now().Unix(),
    }

    // Share our known peers in mesh mode
    if cfg.MeshMode {
        resp.KnownPeers = cfg.Peers
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(resp)
}
