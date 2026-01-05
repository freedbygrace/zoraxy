package main

/*
	Cluster Heartbeat - Peer Health Monitoring

	This file contains the heartbeat loop for monitoring peer health,
	exchanging peer lists in mesh mode, and updating peer online status.

	Related files:
	- cluster_manager.go: Core ClusterManager struct and configuration
	- cluster_sync.go: Broadcast/sync functions for data replication
	- cluster_swarm.go: Docker Swarm service discovery
	- cluster_handlers.go: HTTP API handlers for cluster endpoints
*/

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// StartHeartbeat starts the background heartbeat loop to all peers
func (m *ClusterManager) StartHeartbeat() {
	if m == nil {
		return
	}

	m.mu.Lock()
	if m.heartbeatStop != nil {
		m.mu.Unlock()
		return // Already running
	}
	m.heartbeatStop = make(chan struct{})
	interval := m.heartbeatInterval
	m.mu.Unlock()

	if m.logger != nil {
		m.logger.PrintAndLog("cluster", fmt.Sprintf("Starting heartbeat loop (interval: %v)", interval), nil)
	}

	go func() {
		// Initial heartbeat after short delay
		time.Sleep(2 * time.Second)
		m.sendHeartbeatsToAllPeers()

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				m.sendHeartbeatsToAllPeers()
			case <-m.heartbeatStop:
				if m.logger != nil {
					m.logger.PrintAndLog("cluster", "Heartbeat loop stopped", nil)
				}
				return
			}
		}
	}()
}

// StopHeartbeat stops the heartbeat loop
func (m *ClusterManager) StopHeartbeat() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.heartbeatStop != nil {
		close(m.heartbeatStop)
		m.heartbeatStop = nil
	}
}

// sendHeartbeatsToAllPeers sends heartbeat to each configured peer
func (m *ClusterManager) sendHeartbeatsToAllPeers() {
	m.mu.RLock()
	cfg := m.cfg
	client := m.httpClient
	m.mu.RUnlock()

	if !cfg.Enabled || cfg.SharedSecret == "" {
		return
	}

	peerCount := 0
	for _, peer := range cfg.Peers {
		if !peer.Enabled || peer.BaseURL == "" {
			continue
		}
		peerCount++
		go m.sendHeartbeatToPeer(peer, cfg, client)
	}

	// Log summary periodically (every 5 minutes by default)
	if peerCount > 0 && m.shouldLogRoutine() {
		m.logHeartbeatSummary()
	}
}

// logHeartbeatSummary logs a summary of peer status
func (m *ClusterManager) logHeartbeatSummary() {
	if m.logger == nil {
		return
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	online := 0
	offline := 0
	var onlinePeers []string
	var offlinePeers []string

	for _, peer := range m.cfg.Peers {
		if !peer.Enabled {
			continue
		}
		st := m.peerState[peer.BaseURL]
		if st.Online {
			online++
			name := st.Hostname
			if name == "" {
				name = peer.Name
			}
			onlinePeers = append(onlinePeers, name)
		} else {
			offline++
			offlinePeers = append(offlinePeers, peer.Name)
		}
	}

	if offline == 0 {
		m.logger.PrintAndLog("cluster", fmt.Sprintf("Heartbeat summary: %d peers online (%s)",
			online, strings.Join(onlinePeers, ", ")), nil)
	} else {
		m.logger.PrintAndLog("cluster", fmt.Sprintf("Heartbeat summary: %d online, %d offline (online: %s, offline: %s)",
			online, offline, strings.Join(onlinePeers, ", "), strings.Join(offlinePeers, ", ")), nil)
	}
}

// sendHeartbeatToPeer sends a heartbeat to a single peer and updates its status
func (m *ClusterManager) sendHeartbeatToPeer(peer ClusterPeer, cfg ClusterConfig, client *http.Client) {
	url := strings.TrimRight(peer.BaseURL, "/") + "/cluster/heartbeat"

	// Build heartbeat request with our info
	req := HeartbeatRequest{
		NodeID:        m.nodeID,
		Hostname:      m.hostname,
		AdvertiseAddr: cfg.AdvertiseAddr,
		Timestamp:     time.Now().Unix(),
	}

	// In mesh mode, share our known peers
	if cfg.MeshMode {
		req.KnownPeers = cfg.Peers
	}

	body, err := json.Marshal(req)
	if err != nil {
		return
	}

	httpReq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		m.updatePeerOnlineStatus(peer.BaseURL, false, "", "", err.Error())
		return
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Zoraxy-Cluster-Secret", cfg.SharedSecret)
	httpReq.Header.Set("X-Zoraxy-Node-ID", m.nodeID)
	httpReq.Header.Set("X-Zoraxy-Hostname", m.hostname)
	if cfg.AdvertiseAddr != "" {
		httpReq.Header.Set("X-Zoraxy-Advertise-URL", cfg.AdvertiseAddr)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	httpReq = httpReq.WithContext(ctx)

	resp, err := client.Do(httpReq)
	if err != nil {
		m.updatePeerOnlineStatus(peer.BaseURL, false, "", "", err.Error())
		if m.logger != nil {
			m.logger.Warn("cluster", fmt.Sprintf("Heartbeat failed to %s: %v", peer.BaseURL, err))
		}
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		m.updatePeerOnlineStatus(peer.BaseURL, false, "", "", fmt.Sprintf("HTTP %d", resp.StatusCode))
		return
	}

	// Parse response to get peer's info
	var heartbeatResp HeartbeatResponse
	if err := json.NewDecoder(resp.Body).Decode(&heartbeatResp); err != nil {
		m.updatePeerOnlineStatus(peer.BaseURL, true, "", "", "") // Online but couldn't parse
		return
	}

	// Update peer status with hostname and node ID
	m.updatePeerOnlineStatus(peer.BaseURL, true, heartbeatResp.Hostname, heartbeatResp.NodeID, "")

	// Note: Heartbeat OK messages are logged periodically via logHeartbeatSummary, not per-peer

	// Mesh mode: learn about new peers from response
	if cfg.MeshMode && len(heartbeatResp.KnownPeers) > 0 {
		m.mergeKnownPeers(heartbeatResp.KnownPeers)
	}
}

// updatePeerOnlineStatus updates a peer's online status and metadata
func (m *ClusterManager) updatePeerOnlineStatus(baseURL string, online bool, hostname, nodeID, errMsg string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	st := m.peerState[baseURL]
	st.Online = online
	if hostname != "" {
		st.Hostname = hostname
	}
	if nodeID != "" {
		st.NodeID = nodeID
	}
	if online {
		st.LastSuccessUTC = time.Now().Unix()
		st.LastError = ""
	} else {
		st.LastErrorUTC = time.Now().Unix()
		st.LastError = errMsg
	}
	m.peerState[baseURL] = st
}

// mergeKnownPeers adds any new peers from another node's peer list (mesh mode)
func (m *ClusterManager) mergeKnownPeers(remotePeers []ClusterPeer) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Build set of existing peer URLs
	existingURLs := make(map[string]bool)
	for _, p := range m.cfg.Peers {
		existingURLs[strings.TrimSuffix(p.BaseURL, "/")] = true
	}

	// Also exclude our own advertise address
	if m.cfg.AdvertiseAddr != "" {
		existingURLs[strings.TrimSuffix(m.cfg.AdvertiseAddr, "/")] = true
	}

	added := false
	for _, remote := range remotePeers {
		normalizedURL := strings.TrimSuffix(remote.BaseURL, "/")
		if existingURLs[normalizedURL] {
			continue
		}
		// Don't add ourselves
		if m.isLocalAddress(normalizedURL) {
			continue
		}

		newPeer := ClusterPeer{
			Name:    remote.Name,
			BaseURL: remote.BaseURL,
			Enabled: true,
		}
		m.cfg.Peers = append(m.cfg.Peers, newPeer)
		existingURLs[normalizedURL] = true
		added = true

		if m.logger != nil {
			m.logger.PrintAndLog("cluster", fmt.Sprintf("Mesh: Discovered new peer from gossip: %s (%s)", remote.Name, remote.BaseURL), nil)
		}
	}

	if added {
		go func() {
			if err := m.SaveConfig(); err != nil && m.logger != nil {
				m.logger.PrintAndLog("cluster", "Failed to save config after mesh peer discovery", err)
			}
		}()
	}
}

// isLocalAddress checks if a URL points to this node
func (m *ClusterManager) isLocalAddress(url string) bool {
	// Check against advertise address
	if m.cfg.AdvertiseAddr != "" && strings.TrimSuffix(url, "/") == strings.TrimSuffix(m.cfg.AdvertiseAddr, "/") {
		return true
	}
	// Check against local IPs
	for ip := range m.localIPs {
		if strings.Contains(url, ip) {
			return true
		}
	}
	return false
}

// MergeKnownPeersPublic is a public wrapper for mergeKnownPeers for use from handlers
func (m *ClusterManager) MergeKnownPeersPublic(remotePeers []ClusterPeer) {
	if m == nil {
		return
	}
	m.mergeKnownPeers(remotePeers)
}

