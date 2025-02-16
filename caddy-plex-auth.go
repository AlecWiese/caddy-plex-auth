package caddy-plex-auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(PlexOverseerrHandler{})
}

// PlexOverseerrHandler handles Plex token exchange with Overseerr
type PlexOverseerrHandler struct {
    OverseerrURL string `json:"overseerr_url,omitempty"`
    // Add identifier type
    IdentifierType string `json:"identifier_type,omitempty" default:"email"`
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
	return nil
}

// Validate implements caddy.Validator.
func (h *PlexOverseerrHandler) Validate() error {
	if h.OverseerrURL == "" {
		return fmt.Errorf("overseerr_url is required")
	}
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (h *PlexOverseerrHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
    // Get the identifier from the appropriate claim
    var identifier string
    switch h.IdentifierType {
    case "email":
        identifier = r.Header.Get("X-Plex-Email") // Set by caddy-security from claims
    case "uid":
        identifier = r.Header.Get("X-Plex-UID")
    default:
        return fmt.Errorf("unknown identifier type: %s", h.IdentifierType)
    }

	// Check if we already have a session cookie
	if _, err := r.Cookie("connect.sid"); err == nil {
		return next.ServeHTTP(w, r)
	}

	// Create the auth request body
    authBody := map[string]interface{}{
        "authToken": plexToken,
        "identifier": identifier,
    }

	// Make the auth request to Overseerr
	authReq, err := http.NewRequest(
		"POST",
		fmt.Sprintf("%s/api/v1/auth/plex", h.OverseerrURL),
		bytes.NewBuffer(jsonBody),
	)
	if err != nil {
		return err
	}
	authReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	authResp, err := client.Do(authReq)
	if err != nil {
		return err
	}
	defer authResp.Body.Close()

	if authResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(authResp.Body)
		return fmt.Errorf("auth failed: %s", string(body))
	}

	// Get the session cookie
	var sessionCookie *http.Cookie
	for _, cookie := range authResp.Cookies() {
		if cookie.Name == "connect.sid" {
			sessionCookie = cookie
			break
		}
	}

	if sessionCookie == nil {
		return fmt.Errorf("no session cookie in response")
	}

	// Add the cookie to the request
	r.AddCookie(sessionCookie)

	// Continue with the modified request
	return next.ServeHTTP(w, r)
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (h *PlexOverseerrHandler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if !d.Args(&h.OverseerrURL) {
			return d.ArgErr()
		}
	}
	return nil
}

// Interface guards
var (
	_ caddy.Provisioner           = (*PlexOverseerrHandler)(nil)
	_ caddy.Validator            = (*PlexOverseerrHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*PlexOverseerrHandler)(nil)
	_ caddyfile.Unmarshaler      = (*PlexOverseerrHandler)(nil)
)