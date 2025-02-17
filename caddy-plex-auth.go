package caddyplexauth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// Provider wraps the provider implementation as a Caddy module.
type Provider struct{ *PlexOverseerrHandler }

func init() {
	caddy.RegisterModule(Provider{})
}

// CaddyModule returns the Caddy module information.
func (Provider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "plex.auth",
		New: func() caddy.Module { return &Provider{new(PlexOverseerrHandler)} },
	}
}

// Provision implements caddy.Provisioner.
func (p *Provider) Provision(ctx caddy.Context) error {
	return p.PlexOverseerrHandler.Provision(ctx)
}

// PlexOverseerrHandler handles Plex token exchange with Overseerr
type PlexOverseerrHandler struct {
	// The Overseerr base URL
	OverseerrURL string `json:"overseerr_url,omitempty"`
	// The type of identifier to use (email or uid)
	IdentifierType string `json:"identifier_type,omitempty"`
	// Enable debug logging
	Debug bool `json:"debug,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (PlexOverseerrHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.plexoverseerr",
		New: func() caddy.Module { return new(PlexOverseerrHandler) },
	}
}

// Provision implements caddy.Provisioner.
func (h *PlexOverseerrHandler) Provision(ctx caddy.Context) error {
	if h.OverseerrURL == "" {
		h.OverseerrURL = "http://overseerr:5055"
	}
	if h.IdentifierType == "" {
		h.IdentifierType = "email"
	}
	return nil
}

// Validate implements caddy.Validator.
func (h *PlexOverseerrHandler) Validate() error {
	if h.OverseerrURL == "" {
		return fmt.Errorf("overseerr_url is required")
	}
	if h.IdentifierType != "email" && h.IdentifierType != "uid" {
		return fmt.Errorf("identifier_type must be either 'email' or 'uid'")
	}
	return nil
}

func (h *PlexOverseerrHandler) logDebug(format string, v ...interface{}) {
	if h.Debug {
		log.Printf("[plexoverseerr] "+format, v...)
	}
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (h *PlexOverseerrHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Extract Plex token from Authorization header
	plexToken := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if plexToken == "" {
		h.logDebug("No Plex token found in Authorization header")
		return next.ServeHTTP(w, r)
	}

	// Check if we already have a session cookie
	if _, err := r.Cookie("connect.sid"); err == nil {
		h.logDebug("Existing session cookie found, skipping token exchange")
		return next.ServeHTTP(w, r)
	}

	// Get the identifier based on type
	var identifier string
	switch h.IdentifierType {
	case "email":
		identifier = r.Header.Get("X-Plex-Email")
		h.logDebug("Using email identifier: %s", identifier)
	case "uid":
		identifier = r.Header.Get("X-Plex-UID")
		h.logDebug("Using UID identifier: %s", identifier)
	}

	if identifier == "" {
		return fmt.Errorf("no %s identifier found in request headers", h.IdentifierType)
	}

	// Create the auth request body
	authBody := map[string]interface{}{
		"authToken":  plexToken,
		"identifier": identifier,
	}
	jsonBody, err := json.Marshal(authBody)
	if err != nil {
		return fmt.Errorf("failed to marshal auth body: %w", err)
	}

	h.logDebug("Making auth request to Overseerr")

	// Make the auth request to Overseerr
	authReq, err := http.NewRequest(
		"POST",
		fmt.Sprintf("%s/api/v1/auth/plex", h.OverseerrURL),
		bytes.NewBuffer(jsonBody),
	)
	if err != nil {
		return fmt.Errorf("failed to create auth request: %w", err)
	}
	authReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	authResp, err := client.Do(authReq)
	if err != nil {
		return fmt.Errorf("auth request failed: %w", err)
	}
	defer authResp.Body.Close()

	if authResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(authResp.Body)
		h.logDebug("Auth failed with status %d: %s", authResp.StatusCode, string(body))
		return fmt.Errorf("auth failed with status %d: %s", authResp.StatusCode, string(body))
	}

	// Get the session cookie
	var sessionCookie *http.Cookie
	for _, cookie := range authResp.Cookies() {
		if (cookie.Name == "connect.sid") {
			sessionCookie = cookie
			break
		}
	}

	if sessionCookie == nil {
		return fmt.Errorf("no session cookie in response")
	}

	h.logDebug("Successfully obtained session cookie")

	// Add the cookie to the request
	r.AddCookie(sessionCookie)

	// Continue with the modified request
	return next.ServeHTTP(w, r)
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (h *PlexOverseerrHandler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "overseerr_url":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.OverseerrURL = d.Val()
			case "identifier_type":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.IdentifierType = d.Val()
			case "debug":
				h.Debug = true
			default:
				return d.Errf("unknown subdirective %s", d.Val())
			}
		}
	}
	return nil
}

// Interface guards
var (
	_ caddy.Provisioner           = (*PlexOverseerrHandler)(nil)
	_ caddy.Validator             = (*PlexOverseerrHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*PlexOverseerrHandler)(nil)
	_ caddyfile.Unmarshaler       = (*PlexOverseerrHandler)(nil)
	_ caddy.Provisioner           = (*Provider)(nil)
)