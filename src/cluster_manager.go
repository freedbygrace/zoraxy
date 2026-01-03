package main

/*
	Cluster Manager - Core Types and Configuration

	This file contains the core ClusterManager struct, configuration types,
	and basic operations for cluster membership management.

	Related files:
	- cluster_sync.go: Broadcast/sync functions for data replication
	- cluster_heartbeat.go: Peer health monitoring via heartbeats
	- cluster_swarm.go: Docker Swarm service discovery
	- cluster_handlers.go: HTTP API handlers for cluster endpoints
*/

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"imuslab.com/zoraxy/mod/info/logger"
)

// ClusterPeer represents a peer node in the cluster
type ClusterPeer struct {
	Name    string `json:"name"`
	BaseURL string `json:"baseUrl"`
	Enabled bool   `json:"enabled"`
}

// ClusterConfig holds the cluster configuration settings
type ClusterConfig struct {
	Enabled      bool          `json:"enabled"`
	SharedSecret string        `json:"sharedSecret"`
	Peers        []ClusterPeer `json:"peers"`
	// Mesh mode: automatically add peers when receiving syncs from unknown nodes
	MeshMode      bool   `json:"meshMode,omitempty"`
	AdvertiseAddr string `json:"advertiseAddr,omitempty"` // URL this node advertises to peers (e.g., "http://192.168.1.10:8000")
	// Swarm discovery settings (optional)
	SwarmEnabled bool   `json:"swarmEnabled,omitempty"`
	SwarmService string `json:"swarmService,omitempty"`
	SwarmPort    int    `json:"swarmPort,omitempty"`
	SwarmScheme  string `json:"swarmScheme,omitempty"`
	// Granular sync toggles (all enabled by default if not specified)
	SyncProxies        *bool `json:"syncProxies,omitempty"`        // Sync proxy endpoints
	SyncCerts          *bool `json:"syncCerts,omitempty"`          // Sync TLS certificates
	SyncRedirects      *bool `json:"syncRedirects,omitempty"`      // Sync redirect rules
	SyncAccessRules    *bool `json:"syncAccessRules,omitempty"`    // Sync access control rules
	SyncGlobalSettings *bool `json:"syncGlobalSettings,omitempty"` // Sync global options
	SyncAPITokens      *bool `json:"syncApiTokens,omitempty"`      // Sync API tokens
}

// ClusterPeerStatus represents the status of a peer node
type ClusterPeerStatus struct {
	Name           string `json:"name"`
	BaseURL        string `json:"baseUrl"`
	Hostname       string `json:"hostname,omitempty"`  // Remote node's hostname
	NodeID         string `json:"nodeId,omitempty"`    // Remote node's UUID
	Online         bool   `json:"online"`              // Whether peer is currently reachable
	LastSuccessUTC int64  `json:"lastSuccessUtc"`
	LastErrorUTC   int64  `json:"lastErrorUtc"`
	LastError      string `json:"lastError"`
}

// ClusterStatus represents the overall cluster status
type ClusterStatus struct {
	NodeID         string              `json:"nodeId"`
	Enabled        bool                `json:"enabled"`
	Peers          []ClusterPeerStatus `json:"peers"`
	SwarmMode      bool                `json:"swarmMode"`
	SwarmService   string              `json:"swarmService,omitempty"`
	MeshMode       bool                `json:"meshMode"`
	AdvertiseAddr  string              `json:"advertiseAddr,omitempty"`
	CertTimestamps map[string]int64    `json:"certTimestamps,omitempty"`
	SyncSources    []SyncSourceInfo    `json:"syncSources,omitempty"` // Nodes syncing TO this node
}

// SyncSourceInfo tracks nodes that are syncing to this node
type SyncSourceInfo struct {
	NodeID       string `json:"nodeId"`
	SourceIP     string `json:"sourceIp"`
	LastSyncUTC  int64  `json:"lastSyncUtc"`
	LastSyncType string `json:"lastSyncType"` // e.g., "proxy", "cert", "redirect", "accessRule"
}

// HeartbeatRequest is sent to peers to check health and exchange info
type HeartbeatRequest struct {
	NodeID        string        `json:"nodeId"`
	Hostname      string        `json:"hostname"`
	AdvertiseAddr string        `json:"advertiseAddr"`
	Timestamp     int64         `json:"timestamp"`
	KnownPeers    []ClusterPeer `json:"knownPeers,omitempty"` // For mesh peer exchange
}

// HeartbeatResponse is returned by a peer in response to heartbeat
type HeartbeatResponse struct {
	NodeID        string        `json:"nodeId"`
	Hostname      string        `json:"hostname"`
	AdvertiseAddr string        `json:"advertiseAddr"`
	Timestamp     int64         `json:"timestamp"`
	KnownPeers    []ClusterPeer `json:"knownPeers,omitempty"` // Mesh: share known peers
}

// ClusterManager handles cluster membership and data synchronization
type ClusterManager struct {
	configPath string
	nodeID     string
	hostname   string // Cached hostname for this node
	logger     *logger.Logger

	mu                 sync.RWMutex
	cfg                ClusterConfig
	peerState          map[string]ClusterPeerStatus // keyed by peer BaseURL
	epVersions         map[string]int64             // endpoint key -> last timestamp
	certVersions       map[string]int64             // certificate domain -> last timestamp
	accessRuleVersions map[string]int64             // access rule ID -> last timestamp
	syncSources        map[string]SyncSourceInfo    // keyed by nodeID - tracks nodes syncing TO us
	httpClient         *http.Client

	// Swarm discovery settings
	swarmMode    bool
	swarmSvcName string
	swarmPort    int
	swarmScheme  string
	swarmStop    chan struct{}
	localIPs     map[string]bool // cache of local IPs to exclude self

	// Heartbeat settings
	heartbeatStop     chan struct{}
	heartbeatInterval time.Duration
}

// NewClusterManager creates a new ClusterManager instance
func NewClusterManager(path, nodeID string, lg *logger.Logger) *ClusterManager {
	hostname, _ := os.Hostname()
	return &ClusterManager{
		configPath:         path,
		nodeID:             nodeID,
		hostname:           hostname,
		logger:             lg,
		peerState:          make(map[string]ClusterPeerStatus),
		epVersions:         make(map[string]int64),
		certVersions:       make(map[string]int64),
		accessRuleVersions: make(map[string]int64),
		syncSources:        make(map[string]SyncSourceInfo),
		httpClient:         &http.Client{Timeout: 10 * time.Second}, // Longer timeout for cert transfers
		localIPs:           make(map[string]bool),
		heartbeatInterval:  15 * time.Second, // Default heartbeat interval
	}
}

// GetHostname returns the cached hostname of this node
func (m *ClusterManager) GetHostname() string {
	return m.hostname
}

// Load reads the cluster configuration from disk
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

// Save writes the cluster configuration to disk
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

// SaveConfig is an alias for Save() for external callers
func (m *ClusterManager) SaveConfig() error {
	return m.Save()
}

// GetConfig returns a copy of the current cluster configuration
func (m *ClusterManager) GetConfig() ClusterConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg
}

// UpdateConfig updates the cluster configuration and handles swarm discovery changes
func (m *ClusterManager) UpdateConfig(newCfg ClusterConfig) error {
	if newCfg.Peers == nil {
		newCfg.Peers = []ClusterPeer{}
	}
	// Default swarm port and scheme if not set
	if newCfg.SwarmPort == 0 {
		newCfg.SwarmPort = 8000
	}
	if newCfg.SwarmScheme == "" {
		newCfg.SwarmScheme = "http"
	}

	m.mu.Lock()
	oldSwarmEnabled := m.swarmMode
	oldSwarmService := m.swarmSvcName
	m.cfg = newCfg
	m.mu.Unlock()

	// Handle swarm discovery changes
	if newCfg.SwarmEnabled && newCfg.SwarmService != "" {
		// Start or restart swarm discovery if settings changed
		if !oldSwarmEnabled || oldSwarmService != newCfg.SwarmService {
			m.StopSwarmDiscovery()
			m.StartSwarmDiscovery(newCfg.SwarmService, newCfg.SwarmPort, newCfg.SwarmScheme, 30*time.Second)
		}
	} else if oldSwarmEnabled {
		// Stop swarm discovery if it was enabled but now disabled
		m.StopSwarmDiscovery()
	}

	return m.Save()
}

// IsEnabled returns true if clustering is enabled and configured
func (m *ClusterManager) IsEnabled() bool {
	if m == nil {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg.Enabled && m.cfg.SharedSecret != ""
}

// CheckSharedSecret validates a shared secret against the configured one
func (m *ClusterManager) CheckSharedSecret(secret string) bool {
	if m == nil {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg.Enabled && m.cfg.SharedSecret != "" && secret == m.cfg.SharedSecret
}

// ValidateClusterRequest validates an incoming cluster sync request
func (m *ClusterManager) ValidateClusterRequest(r *http.Request) bool {
	if m == nil {
		return false
	}
	secret := r.Header.Get("X-Zoraxy-Cluster-Secret")
	return m.CheckSharedSecret(secret)
}

// Sync type check helpers - returns true if sync type is enabled (default true if not set)

func (m *ClusterManager) IsSyncProxiesEnabled() bool {
	if m == nil {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg.SyncProxies == nil || *m.cfg.SyncProxies
}

func (m *ClusterManager) IsSyncCertsEnabled() bool {
	if m == nil {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg.SyncCerts == nil || *m.cfg.SyncCerts
}

func (m *ClusterManager) IsSyncRedirectsEnabled() bool {
	if m == nil {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg.SyncRedirects == nil || *m.cfg.SyncRedirects
}

func (m *ClusterManager) IsSyncAccessRulesEnabled() bool {
	if m == nil {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg.SyncAccessRules == nil || *m.cfg.SyncAccessRules
}

func (m *ClusterManager) IsSyncGlobalSettingsEnabled() bool {
	if m == nil {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg.SyncGlobalSettings == nil || *m.cfg.SyncGlobalSettings
}

func (m *ClusterManager) IsSyncAPITokensEnabled() bool {
	if m == nil {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg.SyncAPITokens == nil || *m.cfg.SyncAPITokens
}

// IsMeshModeEnabled returns true if mesh mode is enabled
func (m *ClusterManager) IsMeshModeEnabled() bool {
	if m == nil {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg.MeshMode
}

// GetAdvertiseAddr returns the advertise address for this node
func (m *ClusterManager) GetAdvertiseAddr() string {
	if m == nil {
		return ""
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg.AdvertiseAddr
}

// SetAdvertiseAddr sets the advertise address for this node
func (m *ClusterManager) SetAdvertiseAddr(addr string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg.AdvertiseAddr = addr
	if m.logger != nil {
		m.logger.PrintAndLog("cluster", fmt.Sprintf("Advertise address set to: %s", addr), nil)
	}
}

// SetMeshMode enables or disables mesh mode
func (m *ClusterManager) SetMeshMode(enabled bool) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg.MeshMode = enabled
	if m.logger != nil {
		if enabled {
			m.logger.PrintAndLog("cluster", "Mesh mode ENABLED - will auto-add peers from incoming syncs", nil)
		} else {
			m.logger.PrintAndLog("cluster", "Mesh mode DISABLED", nil)
		}
	}
}

// AutoAddPeerFromRequest checks if mesh mode is enabled and adds the sender as a peer if not already present
// Returns true if a new peer was added
func (m *ClusterManager) AutoAddPeerFromRequest(r *http.Request, originNodeID string) bool {
	if m == nil {
		return false
	}

	// Check if mesh mode is enabled
	if !m.IsMeshModeEnabled() {
		return false
	}

	// Get the advertise URL from the request header
	advertiseURL := r.Header.Get("X-Zoraxy-Advertise-URL")
	if advertiseURL == "" {
		sourceIP := getRequestSourceIP(r)
		if m.logger != nil {
			m.logger.PrintAndLog("cluster", fmt.Sprintf("Mesh mode: Received sync from %s (node: %s) but no advertise URL header - cannot auto-add peer", sourceIP, originNodeID), nil)
		}
		return false
	}

	// Normalize the URL
	advertiseURL = strings.TrimSuffix(advertiseURL, "/")

	// Check if this peer already exists
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, p := range m.cfg.Peers {
		if strings.TrimSuffix(p.BaseURL, "/") == advertiseURL {
			// Peer already exists
			if m.logger != nil {
				m.logger.PrintAndLog("cluster", fmt.Sprintf("Mesh mode: Peer already exists: %s (node: %s)", advertiseURL, originNodeID), nil)
			}
			return false
		}
	}

	// Add the new peer
	newPeer := ClusterPeer{
		Name:    "mesh-" + originNodeID[:8], // Use first 8 chars of node ID as name
		BaseURL: advertiseURL,
		Enabled: true,
	}
	m.cfg.Peers = append(m.cfg.Peers, newPeer)

	if m.logger != nil {
		m.logger.PrintAndLog("cluster", fmt.Sprintf("Mesh mode: AUTO-ADDED new peer '%s' at %s (node: %s)", newPeer.Name, advertiseURL, originNodeID), nil)
	}

	// Save the config
	go func() {
		if err := m.SaveConfig(); err != nil {
			if m.logger != nil {
				m.logger.PrintAndLog("cluster", fmt.Sprintf("Mesh mode: Failed to save config after adding peer: %v", err), nil)
			}
		} else {
			if m.logger != nil {
				m.logger.PrintAndLog("cluster", "Mesh mode: Config saved after adding new peer", nil)
			}
		}
	}()

	return true
}

// ShouldApplyProxyUpdate checks if a proxy update should be applied based on timestamp
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

// ShouldApplyCertUpdate checks if a certificate update should be applied based on timestamp
func (m *ClusterManager) ShouldApplyCertUpdate(domain string, ts int64) bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	last, ok := m.certVersions[domain]
	if !ok || ts > last {
		m.certVersions[domain] = ts
		return true
	}
	return false
}

// RecordCertTimestamp records a certificate timestamp (used when originating an update)
func (m *ClusterManager) RecordCertTimestamp(domain string, ts int64) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.certVersions[domain] = ts
}

// ShouldAcceptAccessRuleUpdate checks if an incoming access rule update should be accepted
func (m *ClusterManager) ShouldAcceptAccessRuleUpdate(ruleID string, ts int64) bool {
	if m == nil {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if existing, ok := m.accessRuleVersions[ruleID]; ok {
		return ts > existing
	}
	return true
}

// RecordAccessRuleTimestamp records an access rule timestamp
func (m *ClusterManager) RecordAccessRuleTimestamp(ruleID string, ts int64) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.accessRuleVersions[ruleID] = ts
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

// Status returns the current cluster status
func (m *ClusterManager) Status() ClusterStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	res := ClusterStatus{
		NodeID:         m.nodeID,
		Enabled:        m.cfg.Enabled && m.cfg.SharedSecret != "",
		Peers:          []ClusterPeerStatus{},
		SwarmMode:      m.swarmMode,
		SwarmService:   m.swarmSvcName,
		MeshMode:       m.cfg.MeshMode,
		AdvertiseAddr:  m.cfg.AdvertiseAddr,
		CertTimestamps: make(map[string]int64),
		SyncSources:    []SyncSourceInfo{},
	}
	for _, p := range m.cfg.Peers {
		st := m.peerState[p.BaseURL]
		st.Name = p.Name
		st.BaseURL = p.BaseURL
		res.Peers = append(res.Peers, st)
	}
	// Copy cert timestamps
	for k, v := range m.certVersions {
		res.CertTimestamps[k] = v
	}
	// Copy sync sources (nodes syncing TO this node)
	for _, src := range m.syncSources {
		res.SyncSources = append(res.SyncSources, src)
	}
	return res
}

// RecordSyncSource records that a node has synced to us
func (m *ClusterManager) RecordSyncSource(nodeID, sourceIP, syncType string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.syncSources[nodeID] = SyncSourceInfo{
		NodeID:       nodeID,
		SourceIP:     sourceIP,
		LastSyncUTC:  time.Now().UTC().Unix(),
		LastSyncType: syncType,
	}
}

// AutoDetectAdvertiseAddr attempts to automatically determine the advertise address
// Priority: 1) Environment variable, 2) Existing config value, 3) Auto-detect from network interfaces
func (m *ClusterManager) AutoDetectAdvertiseAddr(managementPort int) string {
	if m == nil {
		return ""
	}

	// 1. Check environment variable first (highest priority)
	if envAddr := os.Getenv("ZORAXY_ADVERTISE_ADDR"); envAddr != "" {
		if m.logger != nil {
			m.logger.PrintAndLog("cluster", fmt.Sprintf("Advertise address from environment: %s", envAddr), nil)
		}
		return envAddr
	}

	// 2. Check if already configured (user override)
	m.mu.RLock()
	existingAddr := m.cfg.AdvertiseAddr
	m.mu.RUnlock()
	if existingAddr != "" {
		if m.logger != nil {
			m.logger.PrintAndLog("cluster", fmt.Sprintf("Using configured advertise address: %s", existingAddr), nil)
		}
		return existingAddr
	}

	// 3. Auto-detect from network interfaces
	detectedIP := m.detectBestIP()
	if detectedIP == "" {
		if m.logger != nil {
			m.logger.PrintAndLog("cluster", "Could not auto-detect advertise address - no suitable IP found", nil)
		}
		return ""
	}

	// Determine scheme (default http for management interface)
	scheme := "http"

	// Build the URL
	advertiseAddr := fmt.Sprintf("%s://%s:%d", scheme, detectedIP, managementPort)
	if m.logger != nil {
		m.logger.PrintAndLog("cluster", fmt.Sprintf("Auto-detected advertise address: %s", advertiseAddr), nil)
	}

	return advertiseAddr
}

// detectBestIP returns the best IP address for advertising to peers
// Prefers private network IPs, avoids loopback and link-local addresses
func (m *ClusterManager) detectBestIP() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		if m.logger != nil {
			m.logger.PrintAndLog("cluster", "Failed to get network interfaces for auto-detect", err)
		}
		return ""
	}

	var candidates []string
	var fallbackCandidates []string

	for _, iface := range interfaces {
		// Skip down, loopback, and point-to-point interfaces
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
				continue
			}

			// Prefer IPv4
			if ip4 := ip.To4(); ip4 != nil {
				ipStr := ip4.String()
				// Prioritize private network ranges (more likely to be the LAN IP)
				if isPrivateIP(ip4) {
					candidates = append(candidates, ipStr)
				} else {
					fallbackCandidates = append(fallbackCandidates, ipStr)
				}
			}
		}
	}

	// Return best candidate
	if len(candidates) > 0 {
		// Log all candidates for debugging
		if m.logger != nil && len(candidates) > 1 {
			m.logger.PrintAndLog("cluster", fmt.Sprintf("Multiple IP candidates found: %v (using first)", candidates), nil)
		}
		return candidates[0]
	}
	if len(fallbackCandidates) > 0 {
		return fallbackCandidates[0]
	}

	return ""
}

// isPrivateIP checks if an IP is in a private network range
func isPrivateIP(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		// 10.0.0.0/8
		if ip4[0] == 10 {
			return true
		}
		// 172.16.0.0/12
		if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
			return true
		}
		// 192.168.0.0/16
		if ip4[0] == 192 && ip4[1] == 168 {
			return true
		}
	}
	return false
}

// InitializeAdvertiseAddr sets up the advertise address if mesh mode is enabled
// Should be called after Load() during startup
func (m *ClusterManager) InitializeAdvertiseAddr(managementPort int) {
	if m == nil {
		return
	}

	m.mu.RLock()
	meshMode := m.cfg.MeshMode
	currentAddr := m.cfg.AdvertiseAddr
	m.mu.RUnlock()

	// Only auto-detect if mesh mode is enabled and no address is set
	if meshMode && currentAddr == "" {
		detectedAddr := m.AutoDetectAdvertiseAddr(managementPort)
		if detectedAddr != "" {
			m.mu.Lock()
			m.cfg.AdvertiseAddr = detectedAddr
			m.mu.Unlock()

			if m.logger != nil {
				m.logger.PrintAndLog("cluster", fmt.Sprintf("Mesh mode: Auto-configured advertise address: %s", detectedAddr), nil)
			}

			// Save the auto-detected address
			go func() {
				if err := m.SaveConfig(); err != nil {
					if m.logger != nil {
						m.logger.PrintAndLog("cluster", "Failed to save auto-detected advertise address", err)
					}
				}
			}()
		}
	} else if meshMode && currentAddr != "" {
		if m.logger != nil {
			m.logger.PrintAndLog("cluster", fmt.Sprintf("Mesh mode: Using existing advertise address: %s", currentAddr), nil)
		}
	}
}

