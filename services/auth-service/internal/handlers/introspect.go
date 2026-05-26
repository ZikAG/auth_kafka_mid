package handlers

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/kafkaoauth/auth-service/internal/keycloak"
)

// IntrospectRequest is the optional JSON body for POST /api/v1/introspect.
// The token may also be supplied via an Authorization: Bearer header.
type IntrospectRequest struct {
	Token string `json:"token"`
}

// IntrospectResponse is the JSON body returned by the introspection endpoint.
type IntrospectResponse struct {
	Active   bool     `json:"active"`
	Sub      string   `json:"sub,omitempty"`
	TenantID string   `json:"tenant_id,omitempty"`
	Roles    []string `json:"roles,omitempty"`
	Email    string   `json:"email,omitempty"`
	Exp      int64    `json:"exp,omitempty"`
}

// IntrospectHandler returns a Gin handler for POST /api/v1/introspect.
func IntrospectHandler(kc *keycloak.Client, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Accept token from JSON body or Authorization header.
		var req IntrospectRequest
		// ShouldBindJSON returns an error when the body is empty; that is fine here
		// because the caller may use the Authorization header instead.
		_ = c.ShouldBindJSON(&req)

		token := req.Token
		if token == "" {
			token = bearerToken(c)
		}
		if token == "" {
			logger.Warn("introspect: no token provided")
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "bad_request",
				"message": "token is required (body field or Authorization header)",
			})
			return
		}

		log := logger.With(zap.String("handler", "introspect"))

		result, err := kc.IntrospectToken(c.Request.Context(), token)
		if err != nil {
			var httpErr *keycloak.HTTPError
			if errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusUnauthorized {
				log.Warn("introspect: keycloak rejected service credentials", zap.Error(err))
				c.JSON(http.StatusUnauthorized, gin.H{
					"error":   "unauthorized",
					"message": "service credentials rejected",
				})
				return
			}
			log.Error("introspect: keycloak request failed", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "server_error",
				"message": "introspection service unavailable",
			})
			return
		}

		// An inactive token is still a valid response — return it as-is.
		if !result.Active {
			log.Info("introspect: token is inactive")
			c.JSON(http.StatusOK, IntrospectResponse{Active: false})
			return
		}

		log.Info("introspect: token is active",
			zap.String("sub", result.Sub),
			zap.String("tenant_id", result.TenantID),
		)
		c.JSON(http.StatusOK, IntrospectResponse{
			Active:   true,
			Sub:      result.Sub,
			TenantID: result.TenantID,
			Roles:    result.Roles,
			Email:    result.Email,
			Exp:      result.ExpiresAt,
		})
	}
}
