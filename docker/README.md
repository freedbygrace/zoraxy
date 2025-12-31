# Zoraxy Docker

[![Repo](https://img.shields.io/badge/Docker-Repo-007EC6?labelColor-555555&color-007EC6&logo=docker&logoColor=fff&style=flat-square)](https://hub.docker.com/r/zoraxydocker/zoraxy)
[![Version](https://img.shields.io/docker/v/zoraxydocker/zoraxy/latest?labelColor-555555&color-007EC6&style=flat-square)](https://hub.docker.com/r/zoraxydocker/zoraxy)
[![Size](https://img.shields.io/docker/image-size/zoraxydocker/zoraxy/latest?sort=semver&labelColor-555555&color-007EC6&style=flat-square)](https://hub.docker.com/r/zoraxydocker/zoraxy)
[![Pulls](https://img.shields.io/docker/pulls/zoraxydocker/zoraxy?labelColor-555555&color-007EC6&style=flat-square)](https://hub.docker.com/r/zoraxydocker/zoraxy)

## Usage

If you are attempting to access your service from outside your network, make sure to forward ports 80 and 443 to the Zoraxy host to allow web traffic. If you know how to do this, great! If not, find the manufacturer of your router and search on how to do that. There are too many to be listed here. Read more about it from [whatismyip](https://www.whatismyip.com/port-forwarding/).

In the examples below, make sure to update `/path/to/zoraxy/config/`. If a path is not provided, a Docker volume will be created at the location but it is recommended to store the data at a defined host location or a named Docker volume.

Once setup, access the webui at `http://<host-ip>:8000` to configure Zoraxy. Change the port in the URL if you changed the management port.

### Docker Run

```
docker run -d \
  --name zoraxy \
  --restart unless-stopped \
  --add-host=host.docker.internal:host-gateway \
  -p 80:80 \
  -p 443:443 \
  -p 8000:8000 \
  -v /path/to/zoraxy/config/:/opt/zoraxy/config/ \
  -v /path/to/zoraxy/plugin/:/opt/zoraxy/plugin/ \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e FASTGEOIP="true" \
  -e TZ="America/New_York" \
  zoraxydocker/zoraxy:latest
```

### Docker Compose

```yml
services:
  zoraxy:
    image: zoraxydocker/zoraxy:latest
    container_name: zoraxy
    restart: unless-stopped
    ports:
      - 80:80
      - 443:443
      - 8000:8000
    volumes:
      - /path/to/zoraxy/config/:/opt/zoraxy/config/
      - /path/to/zoraxy/plugin/:/opt/zoraxy/plugin/
      - /var/run/docker.sock:/var/run/docker.sock
    extra_hosts:
      - "host.docker.internal:host-gateway"
    environment:
      FASTGEOIP: "true"
      TZ: "America/New_York"
```

### Ports

| Port | Details |
|:-|:-|
| `80` | HTTP traffic. |
| `443` | HTTPS traffic. |
| `8000` | Management interface. Can be changed with the `PORT` env. |

### Volumes

| Volume | Details |
|:-|:-|
| `/opt/zoraxy/config/` | Zoraxy configuration. |
| `/opt/zoraxy/plugin/` | Zoraxy plugins. |
| `/var/run/docker.sock` | Docker socket. Used for additional functionality with Zoraxy. |

### Extra Hosts
| Host | Details |
|:-|:-|
| `host.docker.internal:host-gateway` | Resolves host.docker.internal to the host’s gateway IP on the Docker bridge network, allowing containers to access services running on the host machine. |

### Environment

Variables are the same as those in [Start Parameters](https://github.com/tobychui/zoraxy?tab=readme-ov-file#start-paramters).

#### General Settings

| Variable | Default | Details |
|:-|:-|:-|
| `AUTORENEW` | `86400` (Integer) | ACME auto TLS/SSL certificate renew check interval. |
| `CFGUPGRADE` | `true` (Boolean) | Enable auto config upgrade if breaking change is detected. |
| `DB` | `auto` (String) | Database backend to use (leveldb, boltdb, auto) Note that fsdb will be used on unsupported platforms like RISCV (default "auto"). |
| `DOCKER` | `true` (Boolean) | Run Zoraxy in docker compatibility mode. |
| `EARLYRENEW` | `30` (Integer) | Number of days to early renew a soon expiring certificate. |
| `ENABLELOG` | `true` (Boolean) | Enable system wide logging, set to false for writing log to STDOUT only. |
| `FASTGEOIP` | `false`  (Boolean) | Enable high speed geoip lookup, require 1GB extra memory (Not recommend for low end devices). |
| `MDNS` | `true` (Boolean) | Enable mDNS scanner and transponder. |
| `MDNSNAME` | `''` (String) | mDNS name, leave empty to use default (zoraxy_{node-uuid}.local). |
| `NOAUTH` | `false` (Boolean) | Disable authentication for management interface. |
| `PLUGIN` | `/opt/zoraxy/plugin/` (String) | Set the path for Zoraxy plugins. Only change this if you know what you are doing. |
| `PORT` | `8000` (Integer) | Management web interface listening port |
| `SSHLB` | `false` (Boolean) | Allow loopback web ssh connection (DANGER). |
| `TZ` | `Etc/UTC` (String) | Define timezone using [standard tzdata values](https://en.wikipedia.org/wiki/List_of_tz_database_time_zones). |
| `UPDATE_GEOIP` | `false` (Boolean) | Download the latest GeoIP data and exit. |
| `VERSION` | `false` (Boolean) | Show version of this server. |
| `WEBFM` | `true` (Boolean) | Enable web file manager for static web server root folder. |
| `WEBROOT` | `./www` (String) | Static web server root folder. Only allow change in start parameters. |
| `ZEROTIER` | `false` (Boolean) | Enable ZeroTier functionality for GAN. |

#### Bootstrap Settings (for headless/automated deployment)

| Variable | Default | Details |
|:-|:-|:-|
| `ZORAXY_ADMIN_USER` | `''` (String) | Admin username to create on first startup. |
| `ZORAXY_ADMIN_PASSWORD` | `''` (String) | Admin password to create on first startup. |
| `ZORAXY_BOOTSTRAP_UI` | `false` (Boolean) | Create a `/admin/` virtual directory on root endpoint for UI access via reverse proxy. |

#### Cluster Replication Settings

| Variable | Default | Details |
|:-|:-|:-|
| `CLUSTER` | `false` (Boolean) | Enable cluster mode for multi-node configuration sync. |
| `CLUSTER_SECRET` | `''` (String) | Shared secret for cluster peer authentication (use a strong random string). |
| `CLUSTER_PEERS` | `''` (String) | Comma-separated list of peer URLs (e.g., `http://node2:8000,http://node3:8000`). |
| `CLUSTER_SWARM` | `false` (Boolean) | Enable Docker Swarm auto-discovery for peers. |
| `CLUSTER_SWARM_SERVICE` | `''` (String) | DNS name for Swarm service discovery (e.g., `tasks.zoraxy`). |
| `CLUSTER_SWARM_PORT` | `8000` (Integer) | Port for Swarm peer communication. |
| `CLUSTER_SWARM_SCHEME` | `http` (String) | Scheme for Swarm peer communication (`http` or `https`). |

> [!IMPORTANT]
> Contrary to the Zoraxy README, Docker usage of the port flag should NOT include the colon. Ex: `-e PORT="8000"` for Docker run and `PORT: "8000"` for Docker compose.

### ZeroTier

If you are running with ZeroTier, make sure to add the following flags to ensure ZeroTier functionality:
  
`--cap_add NET_ADMIN` and `--device /dev/net/tun:/dev/net/tun`

Or for Docker Compose:
```
  cap_add:
    - NET_ADMIN
  devices:
    - /dev/net/tun:/dev/net/tun
```

### Cluster Replication

Zoraxy supports multi-node cluster replication for high availability deployments. Configuration changes (proxy rules, certificates, access rules, redirects) are automatically synchronized across all nodes.

#### Features

- **Automatic Synchronization**: Changes on any node are pushed to all peers
- **Docker Swarm Auto-Discovery**: Automatically discovers peers using DNS-based service discovery
- **Bidirectional Visibility**: Each node shows which peers it syncs to and which peers sync to it
- **Conflict Resolution**: Timestamp-based resolution ensures consistency

#### Docker Swarm Deployment

For Swarm deployments, use the `docker-compose.swarm.yml` file or set these environment variables:

```yaml
environment:
  CLUSTER: "true"
  CLUSTER_SECRET: "your-secure-shared-secret"
  CLUSTER_SWARM: "true"
  CLUSTER_SWARM_SERVICE: "tasks.zoraxy"
  ZORAXY_ADMIN_USER: "admin"
  ZORAXY_ADMIN_PASSWORD: "your-admin-password"
  ZORAXY_BOOTSTRAP_UI: "true"
```

The `tasks.<service-name>` DNS name resolves to all container IPs in the service, enabling automatic peer discovery.

#### Manual Peer Configuration

For non-Swarm deployments, configure peers manually:

```yaml
environment:
  CLUSTER: "true"
  CLUSTER_SECRET: "your-secure-shared-secret"
  CLUSTER_PEERS: "http://node2:8000,http://node3:8000"
```

#### UI Features

When cluster mode is enabled, the management UI shows:
- **Cluster Status**: Current node ID, enabled state, peer count
- **Peer Nodes**: All configured peers with connection status and last seen time
- **Receiving Sync From**: Shows which nodes are actively pushing configuration to this node

### Plugins

Zoraxy includes a (experimental) store to download and use official plugins right from inside Zoraxy, no preparation required.
For those looking to use custom plugins, build your plugins and place them inside the volume `/path/to/zoraxy/plugin/:/opt/zoraxy/plugin/` (Adjust to your actual install location).

### Building

To build the Docker image:
  - Check out the repository/branch.
  - Copy the Zoraxy `src/` directory into the `docker/` (here) directory.
  - Run the build command with `docker build -t zoraxy_build .`
  - You can now use the image `zoraxy_build`
    - If you wish to change the image name, then modify`zoraxy_build` in the previous step and then build again.

