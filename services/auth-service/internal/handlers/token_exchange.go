package handlers

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/kafkaoauth/auth-service/internal/keycloak"
	"github.com/kafkaoauth/auth-service/internal/middleware"
)

// TokenExchangeRequest is the JSON body for POST /api/v1/token-exchange.
type TokenExchangeRequest struct {
	// SubjectToken may be omitted when an Authorization: Bearer header is present.
	SubjectToken   string `json:"subject_token"`
	TargetAudience string `json:"target_audience" binding:"required"`
	TenantID       string `json:"tenant_id"`
}

// TokenExchangeResponse is the JSON body returned on a successful exchange.
type TokenExchangeResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	TenantID    string `json:"tenant_id"`
}

// TokenExchangeHandler returns a Gin handler for POST /api/v1/token-exchange.
func TokenExchangeHandler(kc *keycloak.Client, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req TokenExchangeRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			logger.Warn("token-exchange: invalid request body", zap.Error(err))
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "bad_request",
				"message": "target_audience is required",
			})
			return
		}

		// Resolve subject token: prefer request body, fall back to Authorization header.
		subjectToken := strings.TrimSpace(req.SubjectToken)
		if subjectToken == "" {
			subjectToken = bearerToken(c)
		}
		if subjectToken == "" {
			logger.Warn("token-exchange: subject_token missing")
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "bad_request",
				"message": "subject_token is required (body or Authorization header)",
			})
			return
		}

		log := logger.With(
			zap.String("target_audience", req.TargetAudience),
			zap.String("tenant_id", req.TenantID),
			zap.String("handler", "token-exchange"),
		)

		tokenResp, err := kc.TokenExchange(c.Request.Context(), subjectToken, req.TargetAudience, req.TenantID)
		if err != nil {
			var httpErr *keycloak.HTTPError
			if errors.As(err, &httpErr) {
				switch httpErr.StatusCode {
				case http.StatusUnauthorized, http.StatusForbidden:
					log.Warn("token-exchange: upstream rejected subject token", zap.Error(err))
					c.JSON(http.StatusUnauthorized, gin.H{
						"error":   "unauthorized",
						"message": "subject token is invalid or expired",
					})
					return
				case http.StatusBadRequest:
					log.Warn("token-exchange: bad request to keycloak", zap.Error(err))
					c.JSON(http.StatusBadRequest, gin.H{
						"error":   "bad_request",
						"message": "invalid token exchange parameters",
					})
					return
				}
			}
			log.Error("token-exchange: keycloak request failed", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "server_error",
				"message": "token exchange service unavailable",
			})
			return
		}

		// Record the exchange in the metrics middleware counter (best-effort).
		middleware.RecordTokenExchange(req.TenantID, true)

		log.Info("token-exchange: successful")
		c.JSON(http.StatusOK, TokenExchangeResponse{
			AccessToken: tokenResp.AccessToken,
			TokenType:   tokenResp.TokenType,
			ExpiresIn:   tokenResp.ExpiresIn,
			TenantID:    req.TenantID,
		})
	}
}

// bearerToken extracts the token value from an "Authorization: Bearer <token>" header.
func bearerToken(c *gin.Context) string {
	header := c.GetHeader("Authorization")
	if header == "" {
		return ""
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}
