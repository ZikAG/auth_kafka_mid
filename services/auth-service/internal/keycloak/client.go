package keycloak

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kafkaoauth/auth-service/internal/config"
)

// TokenResponse represents a successful token response from Keycloak.
type TokenResponse struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	Scope            string `json:"scope"`
}

// IntrospectionResponse represents the result of a token introspection request.
type IntrospectionResponse struct {
	Active    bool     `json:"active"`
	Sub       string   `json:"sub"`
	TenantID  string   `json:"tenant_id"`
	Roles     []string `json:"roles"`
	Email     string   `json:"email"`
	ExpiresAt int64    `json:"exp"`
	IssuedAt  int64    `json:"iat"`
}

// keycloakError holds the error body returned by Keycloak on failure.
type keycloakError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func (e *keycloakError) Error() string {
	if e.ErrorDescription != "" {
		return fmt.Sprintf("keycloak error: %s – %s", e.Error, e.ErrorDescription)
	}
	return fmt.Sprintf("keycloak error: %s", e.Error)
}

// Client is an HTTP client for the Keycloak token endpoints.
type Client struct {
	cfg        *config.Config
	httpClient *http.Client
}

// New creates a new Keycloak client with a 10-second timeout.
func New(cfg *config.Config) *Client {
	return &Client{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// DirectAccessGrant authenticates a user via the Resource Owner Password Credentials grant
// (Keycloak "Direct Access Grant") and returns tokens.
func (c *Client) DirectAccessGrant(ctx context.Context, username, password, tenantID string) (*TokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", c.cfg.KeycloakClientID)
	form.Set("client_secret", c.cfg.KeycloakClientSecret)
	form.Set("username", username)
	form.Set("password", password)
	form.Set("scope", "openid")

	// Pass tenant_id as a custom claim hint if non-empty.
	if tenantID != "" {
		form.Set("tenant_id", tenantID)
	}

	return c.postToken(ctx, form)
}

// TokenExchange performs an RFC 8693 token exchange, converting a user access token
// into a short-lived Kafka-specific token for the requested audience.
func (c *Client) TokenExchange(ctx context.Context, subjectToken, targetAudience, tenantID string) (*TokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	form.Set("subject_token", subjectToken)
	form.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
	form.Set("requested_token_type", "urn:ietf:params:oauth:token-type:access_token")
	form.Set("audience", targetAudience)
	form.Set("client_id", c.cfg.KeycloakClientID)
	form.Set("client_secret", c.cfg.KeycloakClientSecret)

	if tenantID != "" {
		form.Set("tenant_id", tenantID)
	}

	return c.postToken(ctx, form)
}

// RefreshToken uses a refresh token to obtain a new access token / refresh token pair.
func (c *Client) RefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("client_id", c.cfg.KeycloakClientID)
	form.Set("client_secret", c.cfg.KeycloakClientSecret)
	form.Set("refresh_token", refreshToken)

	return c.postToken(ctx, form)
}

// IntrospectToken calls the Keycloak introspection endpoint for the supplied token.
func (c *Client) IntrospectToken(ctx context.Context, token string) (*IntrospectionResponse, error) {
	form := url.Values{}
	form.Set("token", token)
	form.Set("client_id", c.cfg.KeycloakClientID)
	form.Set("client_secret", c.cfg.KeycloakClientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.KeycloakIntrospectURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("building introspect request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("introspect request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading introspect response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, parseKeycloakError(resp.StatusCode, body)
	}

	var result IntrospectionResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("decoding introspect response: %w", err)
	}
	return &result, nil
}

// GetJWKS fetches the realm's JSON Web Key Set.
func (c *Client) GetJWKS(ctx context.Context) (json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.KeycloakJWKSURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building JWKS request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("JWKS request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading JWKS response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, parseKeycloakError(resp.StatusCode, body)
	}
	return json.RawMessage(body), nil
}

// HealthCheck verifies that the Keycloak JWKS endpoint is reachable and responds 200.
func (c *Client) HealthCheck(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.KeycloakJWKSURL, nil)
	if err != nil {
		return fmt.Errorf("building health-check request: %w", err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("keycloak unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("keycloak returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// ---- helpers ----------------------------------------------------------------

// postToken sends a form-encoded POST to the Keycloak token endpoint and decodes
// a TokenResponse.
func (c *Client) postToken(ctx context.Context, form url.Values) (*TokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.KeycloakTokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("building token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, parseKeycloakError(resp.StatusCode, body)
	}

	var result TokenResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("decoding token response: %w", err)
	}
	return &result, nil
}

// parseKeycloakError attempts to decode a Keycloak error body; falls back to a
// plain HTTP status error when decoding fails.
func parseKeycloakError(statusCode int, body []byte) error {
	var kerr keycloakError
	if json.Unmarshal(body, &kerr) == nil && kerr.Error != "" {
		return &HTTPError{StatusCode: statusCode, Cause: &kerr}
	}
	return &HTTPError{StatusCode: statusCode, Cause: fmt.Errorf("HTTP %d: %s", statusCode, string(body))}
}

// HTTPError wraps an upstream HTTP error code so callers can inspect the status.
type HTTPError struct {
	StatusCode int
	Cause      error
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("upstream HTTP %d: %v", e.StatusCode, e.Cause)
}

func (e *HTTPError) Unwrap() error { return e.Cause }
