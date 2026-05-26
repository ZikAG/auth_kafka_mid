package handlers

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/kafkaoauth/auth-service/internal/keycloak"
)

// RefreshRequest is the JSON body for POST /api/v1/refresh.
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// RefreshResponse is the JSON body returned on a successful token refresh.
type RefreshResponse struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
}

// RefreshHandler returns a Gin handler for POST /api/v1/refresh.
func RefreshHandler(kc *keycloak.Client, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req RefreshRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			logger.Warn("refresh: invalid request body", zap.Error(err))
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "bad_request",
				"message": "refresh_token is required",
			})
			return
		}

		log := logger.With(zap.String("handler", "refresh"))

		tokenResp, err := kc.RefreshToken(c.Request.Context(), req.RefreshToken)
		if err != nil {
			var httpErr *keycloak.HTTPError
			if errors.As(err, &httpErr) {
				switch httpErr.StatusCode {
				case http.StatusUnauthorized, http.StatusForbidden:
					log.Warn("refresh: token rejected by keycloak", zap.Error(err))
					c.JSON(http.StatusUnauthorized, gin.H{
						"error":   "unauthorized",
						"message": "refresh token is invalid or expired",
					})
					return
				case http.StatusBadRequest:
					log.Warn("refresh: bad request to keycloak", zap.Error(err))
					c.JSON(http.StatusBadRequest, gin.H{
						"error":   "bad_request",
						"message": "invalid refresh token",
					})
					return
				}
			}
			log.Error("refresh: keycloak request failed", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "server_error",
				"message": "token service unavailable",
			})
			return
		}

		log.Info("refresh: successful")
		c.JSON(http.StatusOK, RefreshResponse{
			AccessToken:      tokenResp.AccessToken,
			RefreshToken:     tokenResp.RefreshToken,
			TokenType:        tokenResp.TokenType,
			ExpiresIn:        tokenResp.ExpiresIn,
			RefreshExpiresIn: tokenResp.RefreshExpiresIn,
		})
	}
}
