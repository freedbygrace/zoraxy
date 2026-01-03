package main

/*
	Cluster Swarm - Docker Swarm Service Discovery

	This file contains the Docker Swarm service discovery functionality,
	which uses DNS resolution to automatically discover peer nodes in a
	Docker Swarm deployment.

	Related files:
	- cluster_manager.go: Core ClusterManager struct and configuration
	- cluster_sync.go: Broadcast/sync functions for data replication
	- cluster_heartbeat.go: Peer health monitoring via heartbeats
	- cluster_handlers.go: HTTP API handlers for cluster endpoints
*/

import (
	"fmt"
	"net"
	"os"
	"time"
)

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
			// Log as warning, not error - DNS may not be available yet during startup
			m.logger.Warn("cluster", "Swarm DNS lookup warning for "+dnsName+" (will retry): "+err.Error())
		}
		// Continue without peers - will retry on next interval
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

