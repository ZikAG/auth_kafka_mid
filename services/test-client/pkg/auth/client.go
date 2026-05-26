package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Client is an HTTP client for the auth-service API.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// LoginRequest carries credentials for the /api/v1/login endpoint.
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	TenantID string `json:"tenant_id"`
}

// TokenResponse is the successful response from login or token-exchange.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	TenantID     string `json:"tenant_id"`
}

// TokenExchangeRequest asks the auth-service to exchange a subject token for a
// narrower, audience-specific token (e.g. kafka-broker).
type TokenExchangeRequest struct {
	SubjectToken   string `json:"subject_token"`
	TargetAudience string `json:"target_audience"`
	TenantID       string `json:"tenant_id"`
}

// RefreshRequest carries a refresh token to obtain a new access token.
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// NewClient creates an auth-service Client pointing at baseURL.
func NewClient(baseURL string) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// Login authenticates the user against the auth-service and returns a
// TokenResponse containing the short-lived user access token.
func (c *Client) Login(ctx context.Context, req LoginRequest) (*TokenResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("auth: marshal login request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.baseURL+"/api/v1/login",
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, fmt.Errorf("auth: build login request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("auth: login HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("auth: login returned status %d", resp.StatusCode)
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("auth: decode login response: %w", err)
	}
	return &tokenResp, nil
}

// ExchangeToken exchanges a user-level access token for a token scoped to a
// specific target audience (e.g. "kafka-broker").
func (c *Client) ExchangeToken(ctx context.Context, req TokenExchangeRequest) (*TokenResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("auth: marshal exchange request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.baseURL+"/api/v1/token-exchange",
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, fmt.Errorf("auth: build exchange request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("auth: exchange HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("auth: token-exchange returned status %d", resp.StatusCode)
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("auth: decode exchange response: %w", err)
	}
	return &tokenResp, nil
}

// RefreshToken uses a refresh token to obtain a new access token without
// re-entering credentials.
func (c *Client) RefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	body, err := json.Marshal(RefreshRequest{RefreshToken: refreshToken})
	if err != nil {
		return nil, fmt.Errorf("auth: marshal refresh request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.baseURL+"/api/v1/refresh",
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, fmt.Errorf("auth: build refresh request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("auth: refresh HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("auth: refresh returned status %d", resp.StatusCode)
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("auth: decode refresh response: %w", err)
	}
	return &tokenResp, nil
}

// GetKafkaToken is a convenience helper that:
//  1. Logs in as the given user to obtain a short-lived user access token.
//  2. Exchanges that token for a kafka-broker–scoped token.
//
// It returns the raw JWT string to pass directly to the Kafka SASL/OAUTHBEARER
// mechanism.
func (c *Client) GetKafkaToken(ctx context.Context, username, password, tenantID string) (string, error) {
	// Step 1 – obtain user token via direct access grant.
	loginResp, err := c.Login(ctx, LoginRequest{
		Username: username,
		Password: password,
		TenantID: tenantID,
	})
	if err != nil {
		return "", fmt.Errorf("auth: login for %s/%s: %w", tenantID, username, err)
	}

	// Step 2 – narrow the token to the kafka-broker audience.
	exchangeResp, err := c.ExchangeToken(ctx, TokenExchangeRequest{
		SubjectToken:   loginResp.AccessToken,
		TargetAudience: "kafka-broker",
		TenantID:       tenantID,
	})
	if err != nil {
		return "", fmt.Errorf("auth: token exchange for kafka-broker (%s/%s): %w", tenantID, username, err)
	}

	return exchangeResp.AccessToken, nil
}
