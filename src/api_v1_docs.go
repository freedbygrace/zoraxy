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
          "error": {"type": "string"}
        }
      },
      "Status": {
        "type": "object",
        "properties": {
          "status": {"type": "string"},
          "version": {"type": "string"}
        }
      },
      "Proxy": {
        "type": "object",
        "properties": {
          "rootOrMatchingDomain": {"type": "string"},
          "proxyType": {"type": "integer"},
          "disabled": {"type": "boolean"},
          "activeOrigins": {"type": "array", "items": {"type": "string"}},
          "inactiveOrigins": {"type": "array", "items": {"type": "string"}},
          "bypassGlobalTLS": {"type": "boolean"}
        }
      },
      "ProxyCreate": {
        "type": "object",
        "required": ["type", "origins"],
        "properties": {
          "type": {"type": "string", "enum": ["host", "root"]},
          "origins": {"type": "array", "items": {"type": "string"}},
          "requireTLS": {"type": "boolean"},
          "skipCertValid": {"type": "boolean"},
          "bypassGlobalTLS": {"type": "boolean"},
          "disabled": {"type": "boolean"}
        }
      },
      "AccessRule": {
        "type": "object",
        "properties": {
          "id": {"type": "string"},
          "name": {"type": "string"},
          "desc": {"type": "string"},
          "blacklistEnabled": {"type": "boolean"},
          "whitelistEnabled": {"type": "boolean"}
        }
      },
      "Redirect": {
        "type": "object",
        "properties": {
          "redirectUrl": {"type": "string"},
          "targetUrl": {"type": "string"},
          "forwardChildpath": {"type": "boolean"},
          "statusCode": {"type": "integer"},
          "requireExactMatch": {"type": "boolean"}
        }
      },
      "Certificate": {
        "type": "object",
        "properties": {
          "domain": {"type": "string"}
        }
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
            "content": {
              "application/json": {
                "schema": {"$ref": "#/components/schemas/Status"}
              }
            }
          }
        }
      }
    },
    "/proxies": {
      "get": {
        "summary": "List all proxy rules",
        "tags": ["Proxies"],
        "responses": {
          "200": {
            "description": "List of proxies",
            "content": {
              "application/json": {
                "schema": {"type": "array", "items": {"$ref": "#/components/schemas/Proxy"}}
              }
            }
          }
        }
      }
    },
    "/proxies/{domain}": {
      "get": {
        "summary": "Get proxy by domain",
        "tags": ["Proxies"],
        "parameters": [{"name": "domain", "in": "path", "required": true, "schema": {"type": "string"}}],
        "responses": {"200": {"description": "Proxy details"}, "404": {"description": "Not found"}}
      },
      "post": {
        "summary": "Create or update proxy",
        "tags": ["Proxies"],
        "parameters": [{"name": "domain", "in": "path", "required": true, "schema": {"type": "string"}}],
        "requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/ProxyCreate"}}}},
        "responses": {"200": {"description": "Success"}, "400": {"description": "Bad request"}}
      },
      "delete": {
        "summary": "Delete proxy",
        "tags": ["Proxies"],
        "parameters": [{"name": "domain", "in": "path", "required": true, "schema": {"type": "string"}}],
        "responses": {"200": {"description": "Deleted"}, "404": {"description": "Not found"}}
      }
    },
    "/access-rules": {
      "get": {
        "summary": "List all access rules",
        "tags": ["Access Rules"],
        "responses": {"200": {"description": "List of access rules", "content": {"application/json": {"schema": {"type": "array", "items": {"$ref": "#/components/schemas/AccessRule"}}}}}}
      }
    },
    "/access-rules/{id}": {
      "get": {"summary": "Get access rule", "tags": ["Access Rules"], "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}], "responses": {"200": {"description": "Access rule"}}},
      "post": {"summary": "Create/update access rule", "tags": ["Access Rules"], "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}], "responses": {"200": {"description": "Success"}}},
      "delete": {"summary": "Delete access rule", "tags": ["Access Rules"], "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}], "responses": {"200": {"description": "Deleted"}}}
    },
    "/redirects": {
      "get": {"summary": "List all redirects", "tags": ["Redirects"], "responses": {"200": {"description": "List of redirects", "content": {"application/json": {"schema": {"type": "array", "items": {"$ref": "#/components/schemas/Redirect"}}}}}}},
      "post": {"summary": "Create redirect", "tags": ["Redirects"], "requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Redirect"}}}}, "responses": {"201": {"description": "Created"}}}
    },
    "/redirects/{url}": {
      "put": {"summary": "Update redirect", "tags": ["Redirects"], "parameters": [{"name": "url", "in": "path", "required": true, "schema": {"type": "string"}}], "responses": {"200": {"description": "Updated"}}},
      "delete": {"summary": "Delete redirect", "tags": ["Redirects"], "parameters": [{"name": "url", "in": "path", "required": true, "schema": {"type": "string"}}], "responses": {"200": {"description": "Deleted"}}}
    },
    "/certs": {
      "get": {"summary": "List all certificates", "tags": ["Certificates"], "responses": {"200": {"description": "List of certificates", "content": {"application/json": {"schema": {"type": "array", "items": {"$ref": "#/components/schemas/Certificate"}}}}}}}
    },
    "/certs/{domain}": {
      "get": {"summary": "Get certificate", "tags": ["Certificates"], "parameters": [{"name": "domain", "in": "path", "required": true, "schema": {"type": "string"}}], "responses": {"200": {"description": "Certificate info"}}},
      "delete": {"summary": "Delete certificate", "tags": ["Certificates"], "parameters": [{"name": "domain", "in": "path", "required": true, "schema": {"type": "string"}}], "responses": {"200": {"description": "Deleted"}}}
    },
    "/cluster/status": {
      "get": {"summary": "Get cluster status", "tags": ["Cluster"], "responses": {"200": {"description": "Cluster status including peer connectivity"}}}
    },
    "/cluster/config": {
      "get": {"summary": "Get cluster configuration", "tags": ["Cluster"], "responses": {"200": {"description": "Cluster configuration (secret masked)"}}},
      "put": {"summary": "Update cluster configuration", "tags": ["Cluster"], "requestBody": {"required": true, "content": {"application/json": {"schema": {"type": "object", "properties": {"enabled": {"type": "boolean"}, "sharedSecret": {"type": "string"}, "syncProxies": {"type": "boolean"}, "syncCerts": {"type": "boolean"}, "syncRedirects": {"type": "boolean"}, "syncAccessRules": {"type": "boolean"}}}}}}, "responses": {"200": {"description": "Configuration updated"}}}
    },
    "/cluster/peers": {
      "get": {"summary": "List cluster peers", "tags": ["Cluster"], "responses": {"200": {"description": "List of configured peers"}}},
      "post": {"summary": "Add cluster peer", "tags": ["Cluster"], "requestBody": {"required": true, "content": {"application/json": {"schema": {"type": "object", "required": ["baseUrl"], "properties": {"name": {"type": "string"}, "baseUrl": {"type": "string"}, "enabled": {"type": "boolean"}}}}}}, "responses": {"201": {"description": "Peer added"}}},
      "delete": {"summary": "Remove cluster peer", "tags": ["Cluster"], "parameters": [{"name": "baseUrl", "in": "query", "required": true, "schema": {"type": "string"}}], "responses": {"200": {"description": "Peer removed"}}}
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
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(swaggerUIHTML))
}

// handleOpenAPISpec serves the OpenAPI specification
func (r *APIv1Router) handleOpenAPISpec(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(openAPISpec))
}

