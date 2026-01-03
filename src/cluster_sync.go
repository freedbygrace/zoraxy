package main

/*
	Cluster Sync - Data Replication Functions

	This file contains functions for broadcasting data changes to cluster peers,
	including proxy endpoints, certificates, access rules, redirects, and API tokens.

	Related files:
	- cluster_manager.go: Core ClusterManager struct and configuration
	- cluster_heartbeat.go: Peer health monitoring via heartbeats
	- cluster_swarm.go: Docker Swarm service discovery
	- cluster_handlers.go: HTTP API handlers for cluster endpoints
*/

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"imuslab.com/zoraxy/mod/dynamicproxy"
)

// Sync payload types

// CertSyncPayload represents a certificate being synchronized between nodes
type CertSyncPayload struct {
	OriginNodeID string `json:"originNodeID"`
	Timestamp    int64  `json:"timestamp"`
	Domain       string `json:"domain"`     // Certificate domain/filename (without extension)
	PubKeyPEM    []byte `json:"pubKeyPem"`  // Public key in PEM format
	PrivKeyPEM   []byte `json:"privKeyPem"` // Private key in PEM format
}

// ProxyUpsertRequest represents a proxy endpoint being created or updated
type ProxyUpsertRequest struct {
	OriginNodeID string                      `json:"originNodeID"`
	Timestamp    int64                       `json:"timestamp"`
	Endpoint     *dynamicproxy.ProxyEndpoint `json:"endpoint"`
}

// ProxyDeleteRequest represents a proxy endpoint being deleted
type ProxyDeleteRequest struct {
	OriginNodeID         string `json:"originNodeID"`
	Timestamp            int64  `json:"timestamp"`
	RootOrMatchingDomain string `json:"rootOrMatchingDomain"`
}

// AccessRuleSyncPayload is the payload for syncing access rules
type AccessRuleSyncPayload struct {
	OriginNodeID         string            `json:"originNodeId"`
	Timestamp            int64             `json:"timestamp"`
	ID                   string            `json:"id"`
	Name                 string            `json:"name"`
	Desc                 string            `json:"desc"`
	BlacklistEnabled     bool              `json:"blacklistEnabled"`
	WhitelistEnabled     bool              `json:"whitelistEnabled"`
	WhitelistAllowLocal  bool              `json:"whitelistAllowLocalAndLoopback"`
	WhiteListCountryCode map[string]string `json:"whiteListCountryCode"`
	WhiteListIP          map[string]string `json:"whiteListIP"`
	BlackListCountryCode map[string]string `json:"blackListCountryCode"`
	BlackListIP          map[string]string `json:"blackListIP"`
}

// AccessRuleDeletePayload is the payload for deleting access rules
type AccessRuleDeletePayload struct {
	OriginNodeID string `json:"originNodeId"`
	Timestamp    int64  `json:"timestamp"`
	ID           string `json:"id"`
}

// RedirectSyncPayload is the payload for syncing redirect rules
type RedirectSyncPayload struct {
	OriginNodeID      string `json:"originNodeId"`
	Timestamp         int64  `json:"timestamp"`
	RedirectURL       string `json:"redirectUrl"`
	TargetURL         string `json:"targetUrl"`
	ForwardChildpath  bool   `json:"forwardChildpath"`
	StatusCode        int    `json:"statusCode"`
	RequireExactMatch bool   `json:"requireExactMatch"`
}

// RedirectDeletePayload is the payload for deleting redirect rules
type RedirectDeletePayload struct {
	OriginNodeID string `json:"originNodeId"`
	Timestamp    int64  `json:"timestamp"`
	RedirectURL  string `json:"redirectUrl"`
}

// APITokenSyncPayload represents an API token being synchronized between nodes
type APITokenSyncPayload struct {
	OriginNodeID string `json:"originNodeId"`
	Timestamp    int64  `json:"timestamp"`
	TokenID      string `json:"tokenId"`
	Name         string `json:"name"`
	TokenHash    string `json:"tokenHash"`
	Scopes       string `json:"scopes"` // JSON encoded array
	CreatedAt    int64  `json:"createdAt"`
	ExpiresAt    int64  `json:"expiresAt"`
	Description  string `json:"description"`
	Disabled     bool   `json:"disabled"`
}

// APITokenDeletePayload represents an API token being deleted
type APITokenDeletePayload struct {
	OriginNodeID string `json:"originNodeId"`
	Timestamp    int64  `json:"timestamp"`
	TokenID      string `json:"tokenId"`
}

// Retry constants for broadcast operations
const (
	maxRetries     = 3
	baseRetryDelay = 1 * time.Second
	maxRetryDelay  = 30 * time.Second
)

// broadcast sends a payload to all enabled peers
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
		// Send to each peer in its own goroutine with retry logic
		go m.sendToPeerWithRetry(ctx, peer, path, body, cfg.SharedSecret, client)
	}
}

// sendToPeerWithRetry sends a payload to a peer with exponential backoff retry
func (m *ClusterManager) sendToPeerWithRetry(ctx context.Context, peer ClusterPeer, path string, body []byte, secret string, client *http.Client) {
	url := strings.TrimRight(peer.BaseURL, "/") + path
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff with jitter
			delay := baseRetryDelay * time.Duration(1<<uint(attempt-1))
			if delay > maxRetryDelay {
				delay = maxRetryDelay
			}
			// Add some jitter (±25%)
			jitter := time.Duration(float64(delay) * 0.25 * (0.5 - float64(time.Now().UnixNano()%100)/100.0))
			delay += jitter

			select {
			case <-ctx.Done():
				m.recordPeerResult(peer.BaseURL, false, "context cancelled")
				return
			case <-time.After(delay):
				// Continue with retry
			}

			if m.logger != nil {
				m.logger.PrintAndLog("cluster", fmt.Sprintf("Retrying sync to %s (attempt %d/%d)", peer.BaseURL, attempt+1, maxRetries+1), nil)
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Zoraxy-Cluster-Secret", secret)
		req.Header.Set("X-Zoraxy-Node-ID", m.nodeID)
		// Include advertise URL for mesh mode peer discovery
		if advertiseAddr := m.GetAdvertiseAddr(); advertiseAddr != "" {
			req.Header.Set("X-Zoraxy-Advertise-URL", advertiseAddr)
		}

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			m.recordPeerResult(peer.BaseURL, true, "")
			if m.logger != nil {
				m.logger.PrintAndLog("cluster", fmt.Sprintf("Synced to peer %s: %s", peer.BaseURL, path), nil)
			}
			return // Success!
		}

		// Non-retryable status codes (client errors except rate limiting)
		if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != 429 {
			m.recordPeerResult(peer.BaseURL, false, resp.Status)
			if m.logger != nil {
				m.logger.PrintAndLog("cluster", "Peer "+url+" returned non-retryable error: "+resp.Status, nil)
			}
			return
		}

		lastErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	// All retries exhausted
	errMsg := "max retries exceeded"
	if lastErr != nil {
		errMsg = lastErr.Error()
	}
	m.recordPeerResult(peer.BaseURL, false, errMsg)
	if m.logger != nil {
		m.logger.PrintAndLog("cluster", fmt.Sprintf("Failed to sync to %s after %d attempts: %s", peer.BaseURL, maxRetries+1, errMsg), nil)
	}
}

// BroadcastProxyUpsert broadcasts a proxy endpoint creation/update to all peers
func (m *ClusterManager) BroadcastProxyUpsert(ctx context.Context, ep *dynamicproxy.ProxyEndpoint) {
	if m == nil || ep == nil {
		return
	}
	if !m.IsEnabled() {
		return
	}
	if !m.IsSyncProxiesEnabled() {
		if m.logger != nil {
			m.logger.PrintAndLog("cluster", "Proxy sync disabled, skipping broadcast for: "+ep.RootOrMatchingDomain, nil)
		}
		return
	}
	if m.logger != nil {
		m.logger.PrintAndLog("cluster", "Broadcasting proxy upsert: "+ep.RootOrMatchingDomain, nil)
	}
	req := ProxyUpsertRequest{
		OriginNodeID: m.nodeID,
		Timestamp:    time.Now().Unix(),
		Endpoint:     ep,
	}
	m.broadcast(ctx, "/cluster/proxy/upsert", req)
}

// BroadcastProxyDelete broadcasts a proxy endpoint deletion to all peers
func (m *ClusterManager) BroadcastProxyDelete(ctx context.Context, rootOrDomain string) {
	if m == nil || rootOrDomain == "" {
		return
	}
	if !m.IsEnabled() {
		return
	}
	if !m.IsSyncProxiesEnabled() {
		if m.logger != nil {
			m.logger.PrintAndLog("cluster", "Proxy sync disabled, skipping delete broadcast for: "+rootOrDomain, nil)
		}
		return
	}
	if m.logger != nil {
		m.logger.PrintAndLog("cluster", "Broadcasting proxy delete: "+rootOrDomain, nil)
	}
	req := ProxyDeleteRequest{
		OriginNodeID:         m.nodeID,
		Timestamp:            time.Now().Unix(),
		RootOrMatchingDomain: rootOrDomain,
	}
	m.broadcast(ctx, "/cluster/proxy/delete", req)
}

// BroadcastCertificate sends a certificate update to all peers
func (m *ClusterManager) BroadcastCertificate(ctx context.Context, domain string, pubKeyPEM, privKeyPEM []byte) {
	if m == nil || domain == "" {
		return
	}
	if !m.IsSyncCertsEnabled() {
		return
	}
	ts := time.Now().Unix()
	m.RecordCertTimestamp(domain, ts)
	req := CertSyncPayload{
		OriginNodeID: m.nodeID,
		Timestamp:    ts,
		Domain:       domain,
		PubKeyPEM:    pubKeyPEM,
		PrivKeyPEM:   privKeyPEM,
	}
	m.broadcast(ctx, "/cluster/certs/sync", req)
}

// BroadcastCertificateFromFiles reads certificate files and broadcasts them
func (m *ClusterManager) BroadcastCertificateFromFiles(ctx context.Context, domain, pubKeyPath, privKeyPath string) error {
	if m == nil {
		return nil
	}
	if !m.IsSyncCertsEnabled() {
		return nil
	}
	pubKey, err := os.ReadFile(pubKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read public key: %w", err)
	}
	privKey, err := os.ReadFile(privKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read private key: %w", err)
	}
	m.BroadcastCertificate(ctx, domain, pubKey, privKey)
	return nil
}

// BroadcastAccessRuleUpsert sends an access rule update to all peers
func (m *ClusterManager) BroadcastAccessRuleUpsert(ctx context.Context, ruleID, name, desc string,
	blacklistEnabled, whitelistEnabled, whitelistAllowLocal bool,
	whiteListCC, whiteListIP, blackListCC, blackListIP map[string]string) {
	if m == nil || ruleID == "" {
		return
	}
	if !m.IsSyncAccessRulesEnabled() {
		return
	}
	ts := time.Now().Unix()
	m.RecordAccessRuleTimestamp(ruleID, ts)
	req := AccessRuleSyncPayload{
		OriginNodeID:         m.nodeID,
		Timestamp:            ts,
		ID:                   ruleID,
		Name:                 name,
		Desc:                 desc,
		BlacklistEnabled:     blacklistEnabled,
		WhitelistEnabled:     whitelistEnabled,
		WhitelistAllowLocal:  whitelistAllowLocal,
		WhiteListCountryCode: whiteListCC,
		WhiteListIP:          whiteListIP,
		BlackListCountryCode: blackListCC,
		BlackListIP:          blackListIP,
	}
	m.broadcast(ctx, "/cluster/access/sync", req)
}

// BroadcastAccessRuleDelete sends an access rule deletion to all peers
func (m *ClusterManager) BroadcastAccessRuleDelete(ctx context.Context, ruleID string) {
	if m == nil || ruleID == "" || ruleID == "default" {
		return
	}
	if !m.IsSyncAccessRulesEnabled() {
		return
	}
	ts := time.Now().Unix()
	req := AccessRuleDeletePayload{
		OriginNodeID: m.nodeID,
		Timestamp:    ts,
		ID:           ruleID,
	}
	m.broadcast(ctx, "/cluster/access/delete", req)
}

// BroadcastRedirectUpsert sends a redirect rule update to all peers
func (m *ClusterManager) BroadcastRedirectUpsert(ctx context.Context, redirectURL, targetURL string, forwardChildpath bool, statusCode int, requireExactMatch bool) {
	if m == nil || redirectURL == "" {
		return
	}
	if !m.IsSyncRedirectsEnabled() {
		return
	}
	ts := time.Now().Unix()
	req := RedirectSyncPayload{
		OriginNodeID:      m.nodeID,
		Timestamp:         ts,
		RedirectURL:       redirectURL,
		TargetURL:         targetURL,
		ForwardChildpath:  forwardChildpath,
		StatusCode:        statusCode,
		RequireExactMatch: requireExactMatch,
	}
	m.broadcast(ctx, "/cluster/redirect/sync", req)
}

// BroadcastRedirectDelete sends a redirect rule deletion to all peers
func (m *ClusterManager) BroadcastRedirectDelete(ctx context.Context, redirectURL string) {
	if m == nil || redirectURL == "" {
		return
	}
	if !m.IsSyncRedirectsEnabled() {
		return
	}
	ts := time.Now().Unix()
	req := RedirectDeletePayload{
		OriginNodeID: m.nodeID,
		Timestamp:    ts,
		RedirectURL:  redirectURL,
	}
	m.broadcast(ctx, "/cluster/redirect/delete", req)
}

// BroadcastAPIToken broadcasts an API token change to all peers
func (m *ClusterManager) BroadcastAPIToken(ctx context.Context, tokenID, name, tokenHash, scopesJSON, description string, createdAt, expiresAt int64, disabled bool) {
	if m == nil {
		return
	}
	if !m.IsSyncAPITokensEnabled() {
		return
	}
	ts := time.Now().Unix()
	req := APITokenSyncPayload{
		OriginNodeID: m.nodeID,
		Timestamp:    ts,
		TokenID:      tokenID,
		Name:         name,
		TokenHash:    tokenHash,
		Scopes:       scopesJSON,
		CreatedAt:    createdAt,
		ExpiresAt:    expiresAt,
		Description:  description,
		Disabled:     disabled,
	}
	m.broadcast(ctx, "/cluster/apitoken/sync", req)
}

// BroadcastAPITokenDelete broadcasts an API token deletion to all peers
func (m *ClusterManager) BroadcastAPITokenDelete(ctx context.Context, tokenID string) {
	if m == nil || tokenID == "" {
		return
	}
	if !m.IsSyncAPITokensEnabled() {
		return
	}
	ts := time.Now().Unix()
	req := APITokenDeletePayload{
		OriginNodeID: m.nodeID,
		Timestamp:    ts,
		TokenID:      tokenID,
	}
	m.broadcast(ctx, "/cluster/apitoken/delete", req)
}

// setupCertificateClusterSync sets up callbacks to broadcast certificate changes to cluster peers
func setupCertificateClusterSync() {
	if clusterManager == nil {
		return
	}

	// Callback for certificate uploads via TLS cert manager
	certCallback := func(domain, pubKeyPath, privKeyPath string) {
		if clusterManager == nil || !clusterManager.IsEnabled() {
			return
		}
		go func() {
			err := clusterManager.BroadcastCertificateFromFiles(context.Background(), domain, pubKeyPath, privKeyPath)
			if err != nil {
				if SystemWideLogger != nil {
					SystemWideLogger.PrintAndLog("cluster", "Failed to broadcast certificate for "+domain, err)
				}
			} else {
				if SystemWideLogger != nil {
					SystemWideLogger.PrintAndLog("cluster", "Broadcasted certificate to cluster peers: "+domain, nil)
				}
			}
		}()
	}

	// Set callback on TLS cert manager
	if tlsCertManager != nil {
		tlsCertManager.SetOnCertChanged(certCallback)
	}

	// Set callback on ACME handler
	if acmeHandler != nil {
		acmeHandler.OnCertObtained = certCallback
	}
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

	// Apply mesh mode flag
	if *clusterMeshMode {
		cfg.MeshMode = true
		modified = true
		SystemWideLogger.PrintAndLog("cluster", "Mesh mode enabled via CLI flag", nil)
	}

	// Apply advertise address (from flag or environment variable)
	// Environment variable takes precedence over flag
	advertiseAddr := *clusterAdvertiseAddr
	if envAddr := os.Getenv("ZORAXY_ADVERTISE_ADDR"); envAddr != "" {
		advertiseAddr = envAddr
		SystemWideLogger.PrintAndLog("cluster", "Advertise address set from ZORAXY_ADVERTISE_ADDR: "+envAddr, nil)
	}
	if advertiseAddr != "" {
		cfg.AdvertiseAddr = advertiseAddr
		modified = true
	}

	if modified {
		if err := clusterManager.UpdateConfig(cfg); err != nil {
			SystemWideLogger.PrintAndLog("cluster", "Failed to apply cluster flags config", err)
		} else {
			SystemWideLogger.PrintAndLog("cluster", "Cluster configuration applied from flags/env", nil)
		}
	}
}

