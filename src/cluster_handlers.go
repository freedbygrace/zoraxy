package main

import (
    "encoding/json"
    "errors"
    "net/http"
    "os"

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

