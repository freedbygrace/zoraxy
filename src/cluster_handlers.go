package main

import (
    "crypto/rand"
    "encoding/base64"
    "encoding/json"
    "errors"
    "net/http"
    "os"
    "path/filepath"
    "strings"

    "imuslab.com/zoraxy/mod/access"
    "imuslab.com/zoraxy/mod/dynamicproxy"
    "imuslab.com/zoraxy/mod/utils"
)

// Admin API: get or update cluster configuration
func HandleClusterConfig(w http.ResponseWriter, r *http.Request) {
    if clusterManager == nil {
        utils.SendErrorResponse(w, "cluster manager not initialized")
        return
    }

    switch r.Method {
    case http.MethodGet:
        cfg := clusterManager.GetConfig()
        js, err := json.Marshal(cfg)
        if err != nil {
            utils.SendErrorResponse(w, "failed to marshal config: "+err.Error())
            return
        }
        utils.SendJSONResponse(w, string(js))
    case http.MethodPost:
        var cfg ClusterConfig
        if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
            utils.SendErrorResponse(w, "invalid json: "+err.Error())
            return
        }
        if cfg.Enabled && cfg.SharedSecret == "" {
            utils.SendErrorResponse(w, "sharedSecret is required when cluster is enabled")
            return
        }
        if err := clusterManager.UpdateConfig(cfg); err != nil {
            utils.SendErrorResponse(w, "failed to save config: "+err.Error())
            return
        }
        utils.SendOK(w)
    default:
        http.Error(w, "405 - Method not allowed", http.StatusMethodNotAllowed)
    }
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

    utils.SendOK(w)
}
