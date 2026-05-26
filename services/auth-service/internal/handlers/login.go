package handlers

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/kafkaoauth/auth-service/internal/keycloak"
)

// LoginRequest is the JSON body for POST /api/v1/login.
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	TenantID string `json:"tenant_id"`
}

// LoginResponse is the JSON body returned on a successful login.
type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	TenantID     string `json:"tenant_id"`
}

// LoginHandler returns a Gin handler for POST /api/v1/login.
func LoginHandler(kc *keycloak.Client, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req LoginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			logger.Warn("login: invalid request body", zap.Error(err))
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "bad_request",
				"message": "username and password are required",
			})
			return
		}

		log := logger.With(
			zap.String("username", req.Username),
			zap.String("tenant_id", req.TenantID),
			zap.String("handler", "login"),
		)

		tokenResp, err := kc.DirectAccessGrant(c.Request.Context(), req.Username, req.Password, req.TenantID)
		if err != nil {
			var httpErr *keycloak.HTTPError
			if errors.As(err, &httpErr) {
				switch httpErr.StatusCode {
				case http.StatusUnauthorized, http.StatusForbidden:
					log.Warn("login: authentication failed", zap.Error(err))
					c.JSON(http.StatusUnauthorized, gin.H{
						"error":   "unauthorized",
						"message": "invalid credentials",
					})
					return
				case http.StatusBadRequest:
					log.Warn("login: bad request to keycloak", zap.Error(err))
					c.JSON(http.StatusBadRequest, gin.H{
						"error":   "bad_request",
						"message": "invalid login parameters",
					})
					return
				}
			}
			log.Error("login: keycloak request failed", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "server_error",
				"message": "authentication service unavailable",
			})
			return
		}

		log.Info("login: successful")
		c.JSON(http.StatusOK, LoginResponse{
			AccessToken:  tokenResp.AccessToken,
			RefreshToken: tokenResp.RefreshToken,
			TokenType:    tokenResp.TokenType,
			ExpiresIn:    tokenResp.ExpiresIn,
			TenantID:     req.TenantID,
		})
	}
}
