# Zoraxy Cluster Mode

Multi-node configuration synchronization for Zoraxy reverse proxy.

## What Gets Synchronized
- Proxy endpoints (HTTP hosts, rules, headers, auth)
- SSL/TLS certificates
- Access control rules (blacklists/whitelists)
- Redirect rules
- API tokens

## Your Test Cluster

### Bootstrap Node (172.16.32.95)

```bash
cd /root
./zoraxy -port=:8000 \
  -admin_user=admin \
  -admin_password=Zoraxy123 \
  -cluster \
  -cluster_secret="zoraxy-cluster-2024" \
  -cluster_mesh \
  -cluster_advertise_addr="http://172.16.32.95:8000" \
  -enable-rest-api \
  -api_token="zrx_test_token_2024"
```

### Slave Node 1 (172.16.32.96)

```bash
cd /root
./zoraxy -port=:8000 \
  -admin_user=admin \
  -admin_password=Zoraxy123 \
  -cluster \
  -cluster_secret="zoraxy-cluster-2024" \
  -cluster_mesh \
  -cluster_advertise_addr="http://172.16.32.96:8000" \
  -cluster_peers="http://172.16.32.95:8000" \
  -enable-rest-api \
  -api_token="zrx_test_token_2024"
```

### Slave Node 2 (172.16.32.97)

```bash
cd /root
./zoraxy -port=:8000 \
  -admin_user=admin \
  -admin_password=Zoraxy123 \
  -cluster \
  -cluster_secret="zoraxy-cluster-2024" \
  -cluster_mesh \
  -cluster_advertise_addr="http://172.16.32.97:8000" \
  -cluster_peers="http://172.16.32.95:8000" \
  -enable-rest-api \
  -api_token="zrx_test_token_2024"
```

## Web UI Access

| Node | URL | Credentials |
|------|-----|-------------|
| Bootstrap | http://172.16.32.95:8000 | admin / Zoraxy123 |
| Slave 1 | http://172.16.32.96:8000 | admin / Zoraxy123 |
| Slave 2 | http://172.16.32.97:8000 | admin / Zoraxy123 |

## REST API Access

```bash
# List proxies
curl -H "Authorization: Bearer zrx_test_token_2024" http://172.16.32.95:8000/api/v1/proxies

# Get cluster status
curl -H "Authorization: Bearer zrx_test_token_2024" http://172.16.32.95:8000/api/v1/cluster/status
```

---

## Generic Quick Start

### Bootstrap Node (First Node)

```bash
./zoraxy -port=:8000 \
  -admin_user=admin \
  -admin_password=YourSecurePassword123 \
  -cluster \
  -cluster_secret="your-shared-secret-here" \
  -cluster_mesh \
  -cluster_advertise_addr="http://BOOTSTRAP_IP:8000" \
  -enable-rest-api \
  -api_token="your-api-token-here"
```

### Slave Nodes

Each slave only needs to know about the bootstrap node. Mesh mode handles discovery of other slaves.

```bash
./zoraxy -port=:8000 \
  -admin_user=admin \
  -admin_password=YourSecurePassword123 \
  -cluster \
  -cluster_secret="your-shared-secret-here" \
  -cluster_mesh \
  -cluster_advertise_addr="http://THIS_NODE_IP:8000" \
  -cluster_peers="http://BOOTSTRAP_IP:8000" \
  -enable-rest-api \
  -api_token="your-api-token-here"
```

## Configuration Flags

| Flag | Description | Example |
|------|-------------|---------|
| `-cluster` | Enable cluster mode | `-cluster` |
| `-cluster_secret` | Shared secret for authentication (all nodes must use same) | `-cluster_secret="mysecret"` |
| `-cluster_peers` | Comma-separated list of peer URLs | `-cluster_peers="http://node1:8000,http://node2:8000"` |
| `-cluster_mesh` | Enable mesh mode for automatic peer discovery | `-cluster_mesh` |
| `-cluster_advertise_addr` | This node's URL that other nodes can reach | `-cluster_advertise_addr="http://192.168.1.10:8000"` |
| `-admin_user` | Initial admin username (only used if no users exist) | `-admin_user=admin` |
| `-admin_password` | Initial admin password (only used if no users exist) | `-admin_password=secret` |
| `-enable-rest-api` | Enable REST API with token authentication | `-enable-rest-api` |
| `-api_token` | Bootstrap API token (creates token with full access) | `-api_token="zrx_mytoken"` |

## Environment Variables

All flags can also be set via environment variables:

| Environment Variable | Equivalent Flag |
|---------------------|-----------------|
| `ZORAXY_ADMIN_USER` | `-admin_user` |
| `ZORAXY_ADMIN_PASSWORD` | `-admin_password` |
| `ZORAXY_API_TOKEN` | `-api_token` |

## How Mesh Mode Works

1. **Bootstrap**: The first node starts with no peers configured
2. **Slaves Join**: Slave nodes start with the bootstrap node as their only peer
3. **Heartbeat**: Every 30 seconds, nodes send heartbeats to all known peers
4. **Gossip**: Heartbeat messages include each node's known peer list
5. **Discovery**: When a node learns about a new peer from gossip, it adds it automatically
6. **Bidirectional**: When the bootstrap receives a sync from a slave, it automatically adds that slave as a peer

### Example: 3-Node Cluster

```
Initial Configuration:
- Node A (bootstrap): peers = []
- Node B: peers = [A]
- Node C: peers = [A]

After first heartbeat cycle:
- Node A: peers = [B, C]  (learned from incoming syncs)
- Node B: peers = [A, C]  (learned C from A's gossip)
- Node C: peers = [A, B]  (learned B from A's gossip)
```

## REST API Access

With `-enable-rest-api` and `-api_token` set, you can access the API:

```bash
# List all proxies
curl -H "Authorization: Bearer your-api-token-here" \
  http://localhost:8000/api/v1/proxies

# Get cluster status
curl -H "Authorization: Bearer your-api-token-here" \
  http://localhost:8000/api/v1/cluster/status
```

## Docker Compose Example

```yaml
version: '3.8'
services:
  zoraxy-bootstrap:
    image: zoraxy:latest
    environment:
      - ZORAXY_ADMIN_USER=admin
      - ZORAXY_ADMIN_PASSWORD=secret123
      - ZORAXY_API_TOKEN=my-api-token
    command: >
      -port=:8000
      -cluster
      -cluster_secret=my-cluster-secret
      -cluster_mesh
      -cluster_advertise_addr=http://zoraxy-bootstrap:8000
      -enable-rest-api
    ports:
      - "8000:8000"
      - "80:80"
      - "443:443"

  zoraxy-slave:
    image: zoraxy:latest
    environment:
      - ZORAXY_ADMIN_USER=admin
      - ZORAXY_ADMIN_PASSWORD=secret123
      - ZORAXY_API_TOKEN=my-api-token
    command: >
      -port=:8000
      -cluster
      -cluster_secret=my-cluster-secret
      -cluster_mesh
      -cluster_advertise_addr=http://zoraxy-slave:8000
      -cluster_peers=http://zoraxy-bootstrap:8000
      -enable-rest-api
    ports:
      - "8001:8000"
    depends_on:
      - zoraxy-bootstrap
```

## Troubleshooting

### Peers Not Discovering Each Other
- Ensure `-cluster_advertise_addr` is set and reachable from other nodes
- Check that `-cluster_secret` matches on all nodes
- Verify firewall allows traffic on the management port (default 8000)

### API Token Not Working
- Ensure `-enable-rest-api` flag is set
- Token must include the `zrx_` prefix when using the API
- Check logs for "Bootstrap API token created" message

### Certificates Not Syncing
- Verify `syncCerts` is enabled in cluster config (default: true)
- Check that the source node has the certificate stored properly

