package main

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "net"
    "net/http"
    "os"
    "path/filepath"
    "strings"
    "sync"
    "time"

    "imuslab.com/zoraxy/mod/dynamicproxy"
    "imuslab.com/zoraxy/mod/info/logger"
)

type ClusterPeer struct {
    Name    string `json:"name"`
    BaseURL string `json:"baseUrl"`
    Enabled bool   `json:"enabled"`
}

type ClusterConfig struct {
    Enabled      bool          `json:"enabled"`
    SharedSecret string        `json:"sharedSecret"`
    Peers        []ClusterPeer `json:"peers"`
}

type ClusterPeerStatus struct {
    Name           string `json:"name"`
    BaseURL        string `json:"baseUrl"`
    LastSuccessUTC int64  `json:"lastSuccessUtc"`
    LastErrorUTC   int64  `json:"lastErrorUtc"`
    LastError      string `json:"lastError"`
}

type ClusterStatus struct {
    NodeID  string              `json:"nodeId"`
    Enabled bool                `json:"enabled"`
    Peers   []ClusterPeerStatus `json:"peers"`
}

type ClusterManager struct {
    configPath string
    nodeID     string
    logger     *logger.Logger

    mu         sync.RWMutex
    cfg        ClusterConfig
    peerState  map[string]ClusterPeerStatus // keyed by peer BaseURL
    epVersions map[string]int64             // endpoint key -> last timestamp
    httpClient *http.Client

    // Swarm discovery settings
    swarmMode    bool
    swarmSvcName string
    swarmPort    int
    swarmScheme  string
    swarmStop    chan struct{}
    localIPs     map[string]bool // cache of local IPs to exclude self
}

func NewClusterManager(path, nodeID string, lg *logger.Logger) *ClusterManager {
    return &ClusterManager{
        configPath: path,
        nodeID:     nodeID,
        logger:     lg,
        peerState:  make(map[string]ClusterPeerStatus),
        epVersions: make(map[string]int64),
        httpClient: &http.Client{Timeout: 5 * time.Second},
        localIPs:   make(map[string]bool),
    }
}

func (m *ClusterManager) Load() error {
    m.mu.Lock()
    defer m.mu.Unlock()

    data, err := os.ReadFile(m.configPath)
    if err != nil {
        if os.IsNotExist(err) {
            m.cfg = ClusterConfig{Enabled: false, Peers: []ClusterPeer{}}
            return nil
        }
        return err
    }

    var cfg ClusterConfig
    if err := json.Unmarshal(data, &cfg); err != nil {
        return err
    }
    if cfg.Peers == nil {
        cfg.Peers = []ClusterPeer{}
    }
    m.cfg = cfg
    return nil
}

func (m *ClusterManager) Save() error {
    m.mu.RLock()
    cfg := m.cfg
    m.mu.RUnlock()

    if err := os.MkdirAll(filepath.Dir(m.configPath), 0775); err != nil {
        return err
    }
    data, err := json.MarshalIndent(cfg, "", " ")
    if err != nil {
        return err
    }
    return os.WriteFile(m.configPath, data, 0775)
}

func (m *ClusterManager) GetConfig() ClusterConfig {
    m.mu.RLock()
    defer m.mu.RUnlock()
    return m.cfg
}

func (m *ClusterManager) UpdateConfig(newCfg ClusterConfig) error {
    if newCfg.Peers == nil {
        newCfg.Peers = []ClusterPeer{}
    }
    m.mu.Lock()
    m.cfg = newCfg
    m.mu.Unlock()
    return m.Save()
}

func (m *ClusterManager) IsEnabled() bool {
    if m == nil {
        return false
    }
    m.mu.RLock()
    defer m.mu.RUnlock()
    return m.cfg.Enabled && m.cfg.SharedSecret != ""
}

func (m *ClusterManager) CheckSharedSecret(secret string) bool {
    if m == nil {
        return false
    }
    m.mu.RLock()
    defer m.mu.RUnlock()
    return m.cfg.Enabled && m.cfg.SharedSecret != "" && secret == m.cfg.SharedSecret
}

func (m *ClusterManager) ShouldApplyProxyUpdate(key string, ts int64) bool {
    if m == nil {
        return false
    }
    m.mu.Lock()
    defer m.mu.Unlock()
    last, ok := m.epVersions[key]
    if !ok || ts > last {
        m.epVersions[key] = ts
        return true
    }
    return false
}

func (m *ClusterManager) recordPeerResult(baseURL string, ok bool, errMsg string) {
    m.mu.Lock()
    defer m.mu.Unlock()
    st := m.peerState[baseURL]
    if ok {
        st.LastSuccessUTC = time.Now().Unix()
        st.LastError = ""
    } else {
        st.LastErrorUTC = time.Now().Unix()
        st.LastError = errMsg
    }
    m.peerState[baseURL] = st
}

func (m *ClusterManager) Status() ClusterStatus {
    m.mu.RLock()
    defer m.mu.RUnlock()
    res := ClusterStatus{
        NodeID:  m.nodeID,
        Enabled: m.cfg.Enabled && m.cfg.SharedSecret != "",
        Peers:   []ClusterPeerStatus{},
    }
    for _, p := range m.cfg.Peers {
        st := m.peerState[p.BaseURL]
        st.Name = p.Name
        st.BaseURL = p.BaseURL
        res.Peers = append(res.Peers, st)
    }
    return res
}

type ProxyUpsertRequest struct {
    OriginNodeID string                        `json:"originNodeID"`
    Timestamp    int64                         `json:"timestamp"`
    Endpoint     *dynamicproxy.ProxyEndpoint   `json:"endpoint"`
}

type ProxyDeleteRequest struct {
    OriginNodeID         string `json:"originNodeID"`
    Timestamp            int64  `json:"timestamp"`
    RootOrMatchingDomain string `json:"rootOrMatchingDomain"`
}

func (m *ClusterManager) broadcast(ctx context.Context, path string, payload interface{}) {
    if m == nil {
        return
    }
    m.mu.RLock()
    cfg := m.cfg
    client := m.httpClient
    m.mu.RUnlock()

    if !cfg.Enabled || cfg.SharedSecret == "" {
        return
    }

    body, err := json.Marshal(payload)
    if err != nil {
        if m.logger != nil {
            m.logger.PrintAndLog("cluster", "Failed to marshal cluster payload", err)
        }
        return
    }

    for _, peer := range cfg.Peers {
        if !peer.Enabled || peer.BaseURL == "" {
            continue
        }
        url := strings.TrimRight(peer.BaseURL, "/") + path
        req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
        if err != nil {
            if m.logger != nil {
                m.logger.PrintAndLog("cluster", "Failed to create request to "+url, err)
            }
            m.recordPeerResult(peer.BaseURL, false, err.Error())
            continue
        }
        req.Header.Set("Content-Type", "application/json")
        req.Header.Set("X-Zoraxy-Cluster-Secret", cfg.SharedSecret)
        req.Header.Set("X-Zoraxy-Node-ID", m.nodeID)
        resp, err := client.Do(req)
        if err != nil {
            if m.logger != nil {
                m.logger.PrintAndLog("cluster", "Failed to send cluster update to "+url, err)
            }
            m.recordPeerResult(peer.BaseURL, false, err.Error())
            continue
        }
        resp.Body.Close()
        if resp.StatusCode >= 200 && resp.StatusCode < 300 {
            m.recordPeerResult(peer.BaseURL, true, "")
        } else {
            msg := resp.Status
            m.recordPeerResult(peer.BaseURL, false, msg)
            if m.logger != nil {
                m.logger.PrintAndLog("cluster", "Peer "+url+" returned "+msg, nil)
            }
        }
    }
}

func (m *ClusterManager) BroadcastProxyUpsert(ctx context.Context, ep *dynamicproxy.ProxyEndpoint) {
    if m == nil || ep == nil {
        return
    }
    req := ProxyUpsertRequest{
        OriginNodeID: m.nodeID,
        Timestamp:    time.Now().Unix(),
        Endpoint:     ep,
    }
    m.broadcast(ctx, "/cluster/proxy/upsert", req)
}

func (m *ClusterManager) BroadcastProxyDelete(ctx context.Context, rootOrDomain string) {
    if m == nil || rootOrDomain == "" {
        return
    }
    req := ProxyDeleteRequest{
        OriginNodeID:         m.nodeID,
        Timestamp:            time.Now().Unix(),
        RootOrMatchingDomain: rootOrDomain,
    }
    m.broadcast(ctx, "/cluster/proxy/delete", req)
}

// applyClusterFlagsConfig applies cluster configuration from command-line flags/environment variables.
// This is called at startup if any cluster flags are set, allowing pre-configuration via Docker Compose or CLI.
func applyClusterFlagsConfig() {
    if clusterManager == nil {
        return
    }

    cfg := clusterManager.GetConfig()
    modified := false

    // Apply enabled flag
    if *clusterEnabled {
        cfg.Enabled = true
        modified = true
    }

    // Apply shared secret
    if *clusterSecret != "" {
        cfg.SharedSecret = *clusterSecret
        modified = true
    }

    // Apply peers from comma-separated list
    if *clusterPeers != "" {
        peers := []ClusterPeer{}
        for i, peerURL := range strings.Split(*clusterPeers, ",") {
            peerURL = strings.TrimSpace(peerURL)
            if peerURL == "" {
                continue
            }
            peers = append(peers, ClusterPeer{
                Name:    fmt.Sprintf("peer%d", i+1),
                BaseURL: peerURL,
                Enabled: true,
            })
        }
        if len(peers) > 0 {
            cfg.Peers = peers
            modified = true
        }
    }

    if modified {
        if err := clusterManager.UpdateConfig(cfg); err != nil {
            SystemWideLogger.PrintAndLog("cluster", "Failed to apply cluster flags config", err)
        } else {
            SystemWideLogger.PrintAndLog("cluster", "Cluster configuration applied from flags/env", nil)
        }
    }
}

// StartSwarmDiscovery starts the Docker Swarm service discovery background task.
// It periodically resolves the service DNS name to find peer IPs and updates the peer list.
func (m *ClusterManager) StartSwarmDiscovery(serviceName string, port int, scheme string, refreshInterval time.Duration) {
    m.mu.Lock()
    m.swarmMode = true
    m.swarmSvcName = serviceName
    m.swarmPort = port
    m.swarmScheme = scheme
    m.swarmStop = make(chan struct{})
    m.mu.Unlock()

    // Cache local IPs to exclude self
    m.refreshLocalIPs()

    // Initial discovery
    m.discoverSwarmPeers()

    // Start background refresh
    go func() {
        ticker := time.NewTicker(refreshInterval)
        defer ticker.Stop()
        for {
            select {
            case <-ticker.C:
                m.refreshLocalIPs()
                m.discoverSwarmPeers()
            case <-m.swarmStop:
                return
            }
        }
    }()

    if m.logger != nil {
        m.logger.PrintAndLog("cluster", fmt.Sprintf("Swarm discovery started for service '%s' on port %d", serviceName, port), nil)
    }
}

// StopSwarmDiscovery stops the background swarm discovery task.
func (m *ClusterManager) StopSwarmDiscovery() {
    m.mu.Lock()
    defer m.mu.Unlock()
    if m.swarmStop != nil {
        close(m.swarmStop)
        m.swarmStop = nil
    }
    m.swarmMode = false
}

// refreshLocalIPs updates the cache of local IP addresses.
func (m *ClusterManager) refreshLocalIPs() {
    localIPs := make(map[string]bool)

    addrs, err := net.InterfaceAddrs()
    if err == nil {
        for _, addr := range addrs {
            if ipnet, ok := addr.(*net.IPNet); ok {
                localIPs[ipnet.IP.String()] = true
            }
        }
    }

    // Also add hostname resolutions
    if hostname, err := os.Hostname(); err == nil {
        if ips, err := net.LookupIP(hostname); err == nil {
            for _, ip := range ips {
                localIPs[ip.String()] = true
            }
        }
    }

    m.mu.Lock()
    m.localIPs = localIPs
    m.mu.Unlock()
}

// discoverSwarmPeers performs DNS lookup for the swarm service and updates peers.
func (m *ClusterManager) discoverSwarmPeers() {
    m.mu.RLock()
    dnsName := m.swarmSvcName
    port := m.swarmPort
    scheme := m.swarmScheme
    localIPs := m.localIPs
    m.mu.RUnlock()

    if dnsName == "" {
        return
    }

    // Resolve the DNS name directly - user specifies full name
    // e.g., "tasks.zoraxy" for all replicas, or "zoraxy" for VIP
    ips, err := net.LookupIP(dnsName)
    if err != nil {
        if m.logger != nil {
            m.logger.PrintAndLog("cluster", "Swarm DNS lookup failed for "+dnsName, err)
        }
        return
    }

    // Build peer list excluding self
    peers := []ClusterPeer{}
    for _, ip := range ips {
        ipStr := ip.String()
        if localIPs[ipStr] {
            continue // Skip self
        }
        peerURL := fmt.Sprintf("%s://%s:%d", scheme, ipStr, port)
        peers = append(peers, ClusterPeer{
            Name:    "swarm-" + ipStr,
            BaseURL: peerURL,
            Enabled: true,
        })
    }

    // Update config with discovered peers
    m.mu.Lock()
    oldPeerCount := len(m.cfg.Peers)
    m.cfg.Peers = peers
    newPeerCount := len(peers)
    m.mu.Unlock()

    if oldPeerCount != newPeerCount && m.logger != nil {
        m.logger.PrintAndLog("cluster", fmt.Sprintf("Swarm discovery: found %d peers", newPeerCount), nil)
    }
}

// IsSwarmMode returns whether swarm discovery is active.
func (m *ClusterManager) IsSwarmMode() bool {
    m.mu.RLock()
    defer m.mu.RUnlock()
    return m.swarmMode
}
