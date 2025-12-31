package main

/*
	REST API v1 Documentation

	Serves OpenAPI/Swagger documentation for the REST API v1.
	Uses Swagger UI for interactive documentation.
*/

import (
	"net/http"
)

// OpenAPI 3.0 specification for REST API v1
const openAPISpec = `{
  "openapi": "3.0.3",
  "info": {
    "title": "Zoraxy REST API",
    "description": "REST API for programmatic access to Zoraxy reverse proxy management. Requires API token authentication.",
    "version": "1.0.0",
    "contact": {
      "name": "Zoraxy",
      "url": "https://zoraxy.aroz.org"
    },
    "license": {
      "name": "AGPL-3.0",
      "url": "https://www.gnu.org/licenses/agpl-3.0.html"
    }
  },
  "servers": [
    {
      "url": "/api/v1",
      "description": "API v1 endpoint"
    }
  ],
  "security": [
    {"bearerAuth": []},
    {"apiKeyAuth": []}
  ],
  "components": {
    "securitySchemes": {
      "bearerAuth": {
        "type": "http",
        "scheme": "bearer",
        "description": "API token in Authorization header"
      },
      "apiKeyAuth": {
        "type": "apiKey",
        "in": "header",
        "name": "X-API-Key",
        "description": "API token in X-API-Key header"
      }
    },
    "schemas": {
      "Error": {
        "type": "object",
        "properties": {
          "error": {"type": "string", "description": "Error message describing what went wrong"}
        },
        "example": {"error": "invalid request body"}
      },
      "Success": {
        "type": "object",
        "properties": {
          "status": {"type": "string", "description": "Status message, typically 'ok'"}
        },
        "example": {"status": "ok"}
      },
      "Status": {
        "type": "object",
        "properties": {
          "status": {"type": "string", "description": "System status ('ok' or 'error')"},
          "version": {"type": "string", "description": "Zoraxy version string"}
        },
        "example": {"status": "ok", "version": "3.1.9"}
      },
      "Proxy": {
        "type": "object",
        "description": "A proxy endpoint configuration",
        "properties": {
          "rootOrMatchingDomain": {"type": "string", "description": "The domain this proxy matches (e.g., 'example.com')"},
          "proxyType": {"type": "integer", "description": "Proxy type: 0=Root (default), 1=Host (domain-based)"},
          "disabled": {"type": "boolean", "description": "Whether this proxy rule is disabled"},
          "activeOrigins": {"type": "array", "items": {"type": "string"}, "description": "List of active upstream origin servers"},
          "inactiveOrigins": {"type": "array", "items": {"type": "string"}, "description": "List of inactive/disabled origin servers"},
          "bypassGlobalTLS": {"type": "boolean", "description": "Whether to bypass global TLS settings for this proxy"}
        },
        "example": {"rootOrMatchingDomain": "api.example.com", "proxyType": 1, "disabled": false, "activeOrigins": ["192.168.1.10:8080"], "inactiveOrigins": [], "bypassGlobalTLS": false}
      },
      "ProxyCreate": {
        "type": "object",
        "description": "Request body for creating or updating a proxy",
        "required": ["type", "origins"],
        "properties": {
          "type": {"type": "string", "enum": ["host", "root"], "description": "'host' for domain-based proxy, 'root' for default/fallback proxy"},
          "origins": {"type": "array", "items": {"type": "string"}, "description": "List of upstream origin servers (IP:port or domain:port)"},
          "requireTLS": {"type": "boolean", "description": "Require TLS when connecting to upstream", "default": false},
          "skipCertValid": {"type": "boolean", "description": "Skip TLS certificate validation for upstream", "default": false},
          "bypassGlobalTLS": {"type": "boolean", "description": "Bypass global TLS settings", "default": false},
          "disabled": {"type": "boolean", "description": "Create the proxy in disabled state", "default": false}
        },
        "example": {"type": "host", "origins": ["192.168.1.10:8080", "192.168.1.11:8080"], "requireTLS": false, "skipCertValid": false}
      },
      "AccessRule": {
        "type": "object",
        "description": "An access control rule for IP/country-based filtering",
        "properties": {
          "ID": {"type": "string", "description": "Unique identifier for the rule"},
          "Name": {"type": "string", "description": "Human-readable name for the rule"},
          "Desc": {"type": "string", "description": "Description of what this rule does"},
          "BlacklistEnabled": {"type": "boolean", "description": "Whether blacklist filtering is enabled"},
          "WhitelistEnabled": {"type": "boolean", "description": "Whether whitelist filtering is enabled"}
        },
        "example": {"ID": "default", "Name": "Default Rule", "Desc": "Default access control", "BlacklistEnabled": false, "WhitelistEnabled": false}
      },
      "Redirect": {
        "type": "object",
        "description": "A URL redirect rule",
        "properties": {
          "RedirectURL": {"type": "string", "description": "The URL path to match for redirection"},
          "TargetURL": {"type": "string", "description": "The destination URL to redirect to"},
          "ForwardChildpath": {"type": "boolean", "description": "Whether to append child paths to the target URL"},
          "StatusCode": {"type": "integer", "description": "HTTP status code for the redirect (301, 302, 307, 308)", "default": 302},
          "RequireExactMatch": {"type": "boolean", "description": "Whether the URL must match exactly (no partial matching)"}
        },
        "example": {"RedirectURL": "/old-path", "TargetURL": "https://example.com/new-path", "ForwardChildpath": true, "StatusCode": 301, "RequireExactMatch": false}
      },
      "Certificate": {
        "type": "object",
        "description": "A TLS/SSL certificate",
        "properties": {
          "domain": {"type": "string", "description": "Domain name the certificate is for"}
        },
        "example": {"domain": "example.com"}
      },
      "ClusterStatus": {
        "type": "object",
        "description": "Current cluster status and peer connectivity",
        "properties": {
          "nodeId": {"type": "string", "description": "This node's unique identifier"},
          "enabled": {"type": "boolean", "description": "Whether clustering is enabled"},
          "peers": {"type": "array", "items": {"$ref": "#/components/schemas/ClusterPeer"}, "description": "List of configured cluster peers"},
          "swarmMode": {"type": "boolean", "description": "Whether Docker Swarm mode is active"},
          "swarmService": {"type": "string", "description": "Docker Swarm service name if in swarm mode"}
        },
        "example": {"nodeId": "node-abc123", "enabled": true, "peers": [], "swarmMode": false}
      },
      "ClusterPeer": {
        "type": "object",
        "description": "A cluster peer node",
        "properties": {
          "Name": {"type": "string", "description": "Human-readable name for the peer"},
          "BaseURL": {"type": "string", "description": "Base URL of the peer node"},
          "Online": {"type": "boolean", "description": "Whether the peer is currently reachable"},
          "LastSeen": {"type": "string", "format": "date-time", "description": "Last successful contact with peer"}
        },
        "example": {"Name": "Node 2", "BaseURL": "http://192.168.1.20:8000", "Online": true, "LastSeen": "2024-01-15T10:30:00Z"}
      },
      "ClusterConfig": {
        "type": "object",
        "description": "Cluster configuration settings",
        "properties": {
          "enabled": {"type": "boolean", "description": "Enable or disable clustering"},
          "sharedSecret": {"type": "string", "description": "Shared secret for cluster authentication (write-only, masked on read)"},
          "syncProxies": {"type": "boolean", "description": "Sync proxy rules across cluster"},
          "syncCerts": {"type": "boolean", "description": "Sync TLS certificates across cluster"},
          "syncRedirects": {"type": "boolean", "description": "Sync redirect rules across cluster"},
          "syncAccessRules": {"type": "boolean", "description": "Sync access rules across cluster"}
        },
        "example": {"enabled": true, "syncProxies": true, "syncCerts": true, "syncRedirects": true, "syncAccessRules": true}
      },
      "ClusterPeerCreate": {
        "type": "object",
        "description": "Request body for adding a cluster peer",
        "required": ["baseUrl"],
        "properties": {
          "name": {"type": "string", "description": "Human-readable name for the peer"},
          "baseUrl": {"type": "string", "description": "Base URL of the peer (e.g., http://192.168.1.20:8000)"},
          "enabled": {"type": "boolean", "description": "Whether the peer is enabled", "default": true}
        },
        "example": {"name": "Node 2", "baseUrl": "http://192.168.1.20:8000", "enabled": true}
      }
    }
  },
  "paths": {
    "/status": {
      "get": {
        "summary": "Get system status",
        "description": "Returns system status and version. No authentication required.",
        "security": [],
        "tags": ["Status"],
        "responses": {
          "200": {
            "description": "System status",
            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Status"}}}
          }
        }
      }
    },
    "/proxies": {
      "get": {
        "summary": "List all proxy rules",
        "description": "Returns all configured proxy endpoints including their origins and status.",
        "tags": ["Proxies"],
        "responses": {
          "200": {
            "description": "Array of proxy configurations",
            "content": {"application/json": {"schema": {"type": "array", "items": {"$ref": "#/components/schemas/Proxy"}}}}
          },
          "401": {"description": "Unauthorized - invalid or missing API token", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      }
    },
    "/proxies/{domain}": {
      "get": {
        "summary": "Get proxy by domain",
        "description": "Returns detailed configuration for a specific proxy endpoint.",
        "tags": ["Proxies"],
        "parameters": [{"name": "domain", "in": "path", "required": true, "schema": {"type": "string"}, "description": "The domain name of the proxy (e.g., 'api.example.com')"}],
        "responses": {
          "200": {"description": "Proxy configuration", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Proxy"}}}},
          "404": {"description": "Proxy not found", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      },
      "post": {
        "summary": "Create or update proxy",
        "description": "Creates a new proxy endpoint or updates an existing one. Use PUT for the same behavior.",
        "tags": ["Proxies"],
        "parameters": [{"name": "domain", "in": "path", "required": true, "schema": {"type": "string"}, "description": "The domain name for the proxy"}],
        "requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ProxyCreate"}}}},
        "responses": {
          "200": {"description": "Proxy created/updated successfully", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Success"}}}},
          "400": {"description": "Invalid request body", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      },
      "delete": {
        "summary": "Delete proxy",
        "description": "Removes a proxy endpoint configuration.",
        "tags": ["Proxies"],
        "parameters": [{"name": "domain", "in": "path", "required": true, "schema": {"type": "string"}, "description": "The domain name of the proxy to delete"}],
        "responses": {
          "200": {"description": "Proxy deleted", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Success"}}}},
          "404": {"description": "Proxy not found", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      }
    },
    "/access-rules": {
      "get": {
        "summary": "List all access rules",
        "description": "Returns all configured access control rules.",
        "tags": ["Access Rules"],
        "responses": {
          "200": {"description": "Array of access rules", "content": {"application/json": {"schema": {"type": "array", "items": {"$ref": "#/components/schemas/AccessRule"}}}}}
        }
      }
    },
    "/access-rules/{id}": {
      "get": {
        "summary": "Get access rule by ID",
        "tags": ["Access Rules"],
        "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}, "description": "The access rule ID"}],
        "responses": {
          "200": {"description": "Access rule details", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/AccessRule"}}}},
          "404": {"description": "Rule not found", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      },
      "post": {
        "summary": "Create or update access rule",
        "tags": ["Access Rules"],
        "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}, "description": "The access rule ID"}],
        "requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/AccessRule"}}}},
        "responses": {
          "200": {"description": "Rule created/updated", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Success"}}}}
        }
      },
      "delete": {
        "summary": "Delete access rule",
        "tags": ["Access Rules"],
        "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}, "description": "The access rule ID to delete"}],
        "responses": {
          "200": {"description": "Rule deleted", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Success"}}}},
          "404": {"description": "Rule not found", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      }
    },
    "/redirects": {
      "get": {
        "summary": "List all redirects",
        "description": "Returns all configured URL redirect rules.",
        "tags": ["Redirects"],
        "responses": {
          "200": {"description": "Array of redirect rules", "content": {"application/json": {"schema": {"type": "array", "items": {"$ref": "#/components/schemas/Redirect"}}}}}
        }
      },
      "post": {
        "summary": "Create redirect",
        "description": "Creates a new URL redirect rule.",
        "tags": ["Redirects"],
        "requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Redirect"}}}},
        "responses": {
          "201": {"description": "Redirect created", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Success"}}}},
          "400": {"description": "Invalid request", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      }
    },
    "/redirects/{url}": {
      "put": {
        "summary": "Update redirect",
        "tags": ["Redirects"],
        "parameters": [{"name": "url", "in": "path", "required": true, "schema": {"type": "string"}, "description": "URL-encoded redirect URL to update"}],
        "requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Redirect"}}}},
        "responses": {
          "200": {"description": "Redirect updated", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Success"}}}}
        }
      },
      "delete": {
        "summary": "Delete redirect",
        "tags": ["Redirects"],
        "parameters": [{"name": "url", "in": "path", "required": true, "schema": {"type": "string"}, "description": "URL-encoded redirect URL to delete"}],
        "responses": {
          "200": {"description": "Redirect deleted", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Success"}}}}
        }
      }
    },
    "/certs": {
      "get": {
        "summary": "List all certificates",
        "description": "Returns all TLS/SSL certificates managed by Zoraxy.",
        "tags": ["Certificates"],
        "responses": {
          "200": {"description": "Array of certificates", "content": {"application/json": {"schema": {"type": "array", "items": {"$ref": "#/components/schemas/Certificate"}}}}}
        }
      }
    },
    "/certs/{domain}": {
      "get": {
        "summary": "Get certificate info",
        "tags": ["Certificates"],
        "parameters": [{"name": "domain", "in": "path", "required": true, "schema": {"type": "string"}, "description": "Domain name of the certificate"}],
        "responses": {
          "200": {"description": "Certificate details", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Certificate"}}}},
          "404": {"description": "Certificate not found", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      },
      "delete": {
        "summary": "Delete certificate",
        "tags": ["Certificates"],
        "parameters": [{"name": "domain", "in": "path", "required": true, "schema": {"type": "string"}, "description": "Domain name of the certificate to delete"}],
        "responses": {
          "200": {"description": "Certificate deleted", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Success"}}}}
        }
      }
    },
    "/cluster/status": {
      "get": {
        "summary": "Get cluster status",
        "description": "Returns current cluster status including node ID and peer connectivity.",
        "tags": ["Cluster"],
        "responses": {
          "200": {"description": "Cluster status", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ClusterStatus"}}}}
        }
      }
    },
    "/cluster/config": {
      "get": {
        "summary": "Get cluster configuration",
        "description": "Returns cluster configuration. Shared secret is masked for security.",
        "tags": ["Cluster"],
        "responses": {
          "200": {"description": "Cluster configuration", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ClusterConfig"}}}}
        }
      },
      "put": {
        "summary": "Update cluster configuration",
        "description": "Updates cluster settings including sync options.",
        "tags": ["Cluster"],
        "requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ClusterConfig"}}}},
        "responses": {
          "200": {"description": "Configuration updated", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Success"}}}}
        }
      }
    },
    "/cluster/peers": {
      "get": {
        "summary": "List cluster peers",
        "description": "Returns all configured cluster peer nodes.",
        "tags": ["Cluster"],
        "responses": {
          "200": {"description": "Array of peers", "content": {"application/json": {"schema": {"type": "array", "items": {"$ref": "#/components/schemas/ClusterPeer"}}}}}
        }
      },
      "post": {
        "summary": "Add cluster peer",
        "description": "Adds a new peer node to the cluster.",
        "tags": ["Cluster"],
        "requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ClusterPeerCreate"}}}},
        "responses": {
          "201": {"description": "Peer added", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Success"}}}},
          "400": {"description": "Invalid request", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      },
      "delete": {
        "summary": "Remove cluster peer",
        "description": "Removes a peer node from the cluster.",
        "tags": ["Cluster"],
        "parameters": [{"name": "baseUrl", "in": "query", "required": true, "schema": {"type": "string"}, "description": "Base URL of the peer to remove"}],
        "responses": {
          "200": {"description": "Peer removed", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Success"}}}}
        }
      }
    }
  }
}`

// Swagger UI HTML template
const swaggerUIHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Zoraxy API Documentation</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
  <style>
    body { margin: 0; padding: 0; }
    .swagger-ui .topbar { display: none; }
  </style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    window.onload = function() {
      SwaggerUIBundle({
        url: "/api/v1/docs/openapi.json",
        dom_id: '#swagger-ui',
        presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
        layout: "BaseLayout"
      });
    };
  </script>
</body>
</html>`

// registerDocsRoutes registers the documentation endpoints
func (r *APIv1Router) registerDocsRoutes() {
	r.mux.HandleFunc("/api/v1/docs", r.handleDocsUI)
	r.mux.HandleFunc("/api/v1/docs/", r.handleDocsUI)
	r.mux.HandleFunc("/api/v1/docs/openapi.json", r.handleOpenAPISpec)
}

// handleDocsUI serves the Swagger UI
func (r *APIv1Router) handleDocsUI(w http.ResponseWriter, req *http.Request) {
	if !isRestAPIDocsEnabled() {
		http.NotFound(w, req)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(swaggerUIHTML))
}

// handleOpenAPISpec serves the OpenAPI specification
func (r *APIv1Router) handleOpenAPISpec(w http.ResponseWriter, req *http.Request) {
	if !isRestAPIDocsEnabled() {
		http.NotFound(w, req)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(openAPISpec))
}

